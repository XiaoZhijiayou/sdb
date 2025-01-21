#include <libsdb/process.hpp>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <libsdb/error.hpp>
#include <libsdb/pipe.hpp>

namespace {
    // 将一个带有给定消息前缀的 errno 表示写入管道中
    void exit_with_perror(sdb::pipe& channel, std::string const& prefix){
            auto message = prefix + ": " + std::strerror(errno);
            channel.write(reinterpret_cast<std::byte*>(message.data()), message.size());
            exit(-1);
        }
}

// 这里面是将子进程识别为被调试的部分，父进程是调试器部分 父进程负责跟踪子进程
/**
 * 启动子进程
 * 选择是否以调试模式启动子进程
 * 允许将子进程的标准输出（stdout）重定向到另一个文件描述符
 * 使用管道（pipe）在子进程和父进程之间传递错误信息
 */
std::unique_ptr<sdb::process>
sdb::process::launch(std::filesystem::path path , bool debug ,std::optional<int> stdout_replacement){
    pipe channel(/*close_on_exec=*/true);
    pid_t pid;
    if((pid = fork()) < 0){
        error::send_errno("fork failed");
    }

    if(pid == 0){
        channel.close_read();

        if(stdout_replacement){
            // 任何输出到 stdout 的内容都会通过 *stdout_replacement 指向的目标进行传输
            if(dup2(*stdout_replacement, STDOUT_FILENO) < 0){
                exit_with_perror(channel, "stdout replacement failed");
            }
        }

        // 将当前的子进程设置成为可以被追踪的形式
        if(debug and ptrace(PTRACE_TRACEME, 0 , nullptr,nullptr) < 0){
            exit_with_perror(channel,"Tracing failed");
        }
        //用于替换当前进程映像的函数调用
        if(execlp(path.c_str(), path.c_str(), nullptr) < 0){
            exit_with_perror(channel, "exec failed");
        }
    }
    channel.close_write();
    auto data = channel.read();
    channel.close_read();
    
    if(data.size() > 0){
        waitpid(pid,nullptr,0);
        auto chars = reinterpret_cast<char*>(data.data());
        //这样就可以让子进程的错误信息传给父进程了
        error::send(std::string(chars,chars + data.size()));
    }
    std::unique_ptr<process> proc (new process(pid, /*terminate_on_end=*/ true,debug));
    if(debug){
        proc->wait_on_signal();
    }
    return proc;
}

std::unique_ptr<sdb::process>
sdb::process::attach(pid_t pid) {
    if (pid == 0) {
        // Error: Invalid PID
        error::send("Invalid PID");
    }
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        // Error: Could not attach
        error::send_errno("Could not attach");
    }

    std::unique_ptr<process> proc (new process(pid, /*terminate_on_end=*/false,/*attached=*/true));
    proc->wait_on_signal();
    return proc;
}

sdb::process::~process(){
    if(pid_ != 0){
        int status;
        if(is_attached_){
            if(state_ == process_state::running){
                //则调试器会通过 kill(pid_, SIGSTOP) 发送一个 SIGSTOP 信号来暂停目标进程
                kill(pid_, SIGSTOP);
                // 然后使用 waitpid(pid_, &status, 0) 来等待进程暂停，并获取进程的状态信息。
                // 这样可以确保目标进程在继续进行任何后续操作之前已经暂停
                waitpid(pid_, &status, 0);
            }
            //调用 ptrace(PTRACE_DETACH) 将调试器与目标进程分离。
            // PTRACE_DETACH 告诉操作系统，调试器不再对目标进程进行调试操作
            ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
            kill(pid_,SIGCONT);
        }
        if(terminate_on_end_){
            kill(pid_,SIGKILL);
            waitpid(pid_, &status, 0);
        }
    }
}

void sdb::process::resume(){
    if(ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0){
        error::send_errno("Could not resume");
    }
    state_ = process_state::running;
}

sdb::stop_reason::stop_reason(int wait_status){
    // 检查进程是否正常退出
    if(WIFEXITED(wait_status)){
        reason = process_state::exited;
        info = WEXITSTATUS(wait_status);
    }
    // 检查进程是否因信号而终止
    else if(WIFSIGNALED(wait_status)){
        reason = process_state::terminated;
        info = WTERMSIG(wait_status);
    }
    // 检查进程是否因接收到停止信号而被暂停
    else if (WIFSTOPPED(wait_status))
    {
        reason = process_state::stopped;
        info = WSTOPSIG(wait_status);
    }
}

//用于等待目标进程发送信号并处理该信号
sdb::stop_reason sdb::process::wait_on_signal(){
    int wait_status;
    int options = 0;
    if(waitpid(pid_, &wait_status, options) < 0){
        error::send_errno("waitpid failed");
    }
    stop_reason reason(wait_status);
    state_ = reason.reason;

    if(is_attached_ and state_ == process_state::stopped){
        read_all_registers();
    }
    return reason;
}

void sdb::process::read_all_registers(){
    if(ptrace(PTRACE_GETREGS, pid_, nullptr,&get_registers().data_.regs) < 0){
        error::send_errno("Could not read GPR reigsters");
    }
    if(ptrace(PTRACE_GETFPREGS, pid_, nullptr, &get_registers().data_.i387) < 0){
        error::send_errno("Could not read FPR registers");
    }
    for(int i = 0; i < 8; ++i){
        auto id = static_cast<int>(register_id::dr0) + 1;
        auto info = register_info_by_id(static_cast<register_id>(id));

        errno = 0;
        std::int64_t data = ptrace(PTRACE_PEEKUSER, pid_,info.offset, nullptr);

        if(errno != 0) error::send_errno("Could not read debug register");
        get_registers().data_.u_debugreg[i] = data;
    }
}

void sdb::process::write_user_area(std::size_t offset, std::uint64_t data){
    if(ptrace(PTRACE_POKEDATA, pid_, offset, data) < 0){
        error::send_errno("Could not write to user area");
    }
}

void sdb::process::write_fprs(const user_fpregs_struct& fprs){
    if(ptrace(PTRACE_SETFPXREGS, pid_, nullptr,&fprs) < 0){
        error::send_errno("Could not write floating point registers");
    }
}

void sdb::process::write_gprs(const user_regs_struct& gprs){
    if (ptrace(PTRACE_SETREGS, pid_, nullptr, &gprs) < 0) {
        error::send_errno("Could not write general purpose registers");
    }
}