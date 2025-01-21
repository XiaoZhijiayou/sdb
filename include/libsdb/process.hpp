#ifndef SDB_PROCESS_HPP
#define SDB_PROCESS_HPP

#include <filesystem>
#include <memory>
#include <sys/types.h>
#include <libsdb/registers.hpp>
#include <optional>

namespace sdb{

    enum class process_state {
        stopped,
        running,
        exited,
        terminated
    };

    struct stop_reason {
        /**
         * 它解析了 wait_status，并根据进程的退出或暂停状态
         */
        stop_reason(int wait_status);

        process_state reason;
        std::uint8_t info;
    };

    class process {
        public:
            ~process();
            // 接收需要启动的程序的路径
            static std::unique_ptr<process> launch(std::filesystem::path path 
                    , bool debug = true
                    , std::optional<int> stdout_replacement = std::nullopt);
            // 接收要附加到的现有进程的PID
            static std::unique_ptr<process> attach(pid_t pid);

            /**
             * 继续进行调试、追踪
             */
            void resume();

            /**
             * 
             */
            stop_reason wait_on_signal();

            pid_t pid() const {return pid_;}

            process() = delete;
            process(const process&) = delete;
            process& operator=(const process&) = delete;

            process_state state() const { return state_; }

            registers& get_registers() {return *registers_;}

            const registers& get_registers() const {return *registers_;}

            void write_user_area(std::size_t offset, std::uint64_t data);

            void write_fprs(const user_fpregs_struct& fprs);
            void write_gprs(const user_regs_struct& gprs);


        private:
            process(pid_t pid, bool terminate_on_end ,bool is_attached)
                : pid_(pid), 
                terminate_on_end_(terminate_on_end),
                is_attached_(is_attached),
                registers_(new registers(*this)){}

            void read_all_registers();

            pid_t pid_ = 0;

            //该变量决定了在进程结束时，是否自动终止调试器本身或销毁 process 对象
            bool terminate_on_end_ = true;

            process_state state_ = process_state::stopped;
            
            bool is_attached_ = true;
            std::unique_ptr<registers> registers_; 
    };

}


#endif