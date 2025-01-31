#ifndef SDB_PROCESS_HPP
#define SDB_PROCESS_HPP

#include <filesystem>
#include <memory>
#include <optional>
#include <sys/types.h>
#include <libsdb/bit.hpp>
#include <libsdb/registers.hpp>
#include <vector>
#include <libsdb/breakpoint_site.hpp>
#include <libsdb/stoppoint_collection.hpp>
#include <libsdb/watchpoint.hpp>
namespace sdb {
    class syscall_catch_policy {
    public:
        enum mode {
            none, some, all
        };

        static syscall_catch_policy catch_all() {
            return { mode::all, {}};
        }
        static syscall_catch_policy catch_none() {
            return { mode::none, {} };
        }

        static syscall_catch_policy catch_some(std::vector<int> to_catch) {
            return { mode::some, std::move(to_catch) };
        }

        mode get_mode() const {return mode_;}
        const std::vector<int>& get_to_catch() const {return to_catch_;}

    private:
        syscall_catch_policy(mode mode, std::vector<int> to_catch) :
            mode_(mode), to_catch_(to_catch) {}
        mode mode_ = mode::none;
        std::vector<int> to_catch_;
    };


    enum class process_state {
        stopped,
        running,
        exited,
        terminated
    };



    struct syscall_information {
        std::uint16_t id;
        bool entry;
        union {
            std::array<std::uint16_t, 6> args;
            std::int64_t ret;
        };
    };

    enum class trap_type {
        single_step, software_break, hardware_break, syscall, unknown
    };

    struct stop_reason {
		stop_reason(int wait_status);

		process_state reason;
		std::uint8_t info;
		std::optional<trap_type> trap_reason;
		std::optional<syscall_information> syscall_info;
	};


    class process {
    public:
        ~process();
        static std::unique_ptr<process> launch(std::filesystem::path path,
            bool debug = true,
            std::optional<int> stdout_replacement = std::nullopt);
        static std::unique_ptr<process> attach(pid_t pid);

        void resume();
        stop_reason wait_on_signal();

        process() = delete;
        process(const process&) = delete;
        process& operator=(const process&) = delete;

        process_state state() const { return state_; }
        pid_t pid() const { return pid_; }

        registers& get_registers() { return *registers_; }
        const registers& get_registers() const { return *registers_; }

        //将数据写入用户区域的指定偏移位置
        void write_user_area(std::size_t offset, std::uint64_t data);
        //将浮点寄存器结构体的数据写入用户区域
        void write_fprs(const user_fpregs_struct& fprs);
        //将通用寄存器结构体的数据写入用户区域
        void write_gprs(const user_regs_struct& gprs);

        // 读取用户区域的指定偏移位置的数据
        std::vector<std::byte> read_memory(virt_addr address, std::size_t amount) const;
      
        std::vector<std::byte> read_memory_without_traps(virt_addr address, std::size_t amount) const;

        //将数据写入指定地址
        void write_memory(virt_addr address, span<const std::byte> data);

        breakpoint_site& create_breakpoint_site(virt_addr address, bool hardware = false, bool internal = false);

        stoppoint_collection<breakpoint_site>&
        breakpoint_sites() { return breakpoint_sites_;}
        

        const stoppoint_collection<breakpoint_site>&
        breakpoint_sites()  const { return breakpoint_sites_;}

        virt_addr get_pc() const {
            return virt_addr{
                get_registers().read_by_id_as<std::uint64_t>(register_id::rip)
            };
        }
        //实现单步执行的策略
        sdb::stop_reason step_instruction();

        // 这个rip是指令指针寄存器
        void set_pc(virt_addr address) {
            get_registers().write_by_id(register_id::rip, address.addr());
        }

        template <class T>
        T read_memory_as(virt_addr address) const {
            auto data = read_memory(address, sizeof(T));
            return from_bytes<T>(data.data());
        }

        //设置硬件断点外部接口部分
        int set_hardware_breakpoint( breakpoint_site::id_type id, virt_addr address);
        
        // 清除硬件断点外部接口部分
        void clear_hardware_stoppoint(int index);

        int set_watchpoint(
            watchpoint::id_type id, virt_addr address,
            stoppoint_mode mode, std::size_t size);

        watchpoint& create_watchpoint(virt_addr address, stoppoint_mode mode, std::size_t size);

        stoppoint_collection<watchpoint>& watchpoints() {
            return watchpoints_;
        }

        const stoppoint_collection<watchpoint>& watchpoints() const {
            return watchpoints_;
        }

        // 表示进程是因为接收到信号而停止
        void augment_stop_reason(stop_reason& reason);

        std::variant<breakpoint_site::id_type, watchpoint::id_type>
        get_current_hardware_stoppoint() const;

        void set_syscall_catch_policy(syscall_catch_policy info) {
            syscall_catch_policy_ = std::move(info);
        }

    private:
        process(pid_t pid, bool terminate_on_end, bool is_attached)
            : pid_(pid), terminate_on_end_(terminate_on_end),
            is_attached_(is_attached), registers_(new registers(*this))
        {}

        void read_all_registers();

        sdb::stop_reason maybe_resume_from_syscall(const stop_reason& reason);

        //debug的进程id
        pid_t pid_ = 0;
        //当前调试器结束的时候，是否对子进程进行终止操作
        bool terminate_on_end_ = true;
        //
        process_state state_ = process_state::stopped;
        bool is_attached_ = true;

        //一个管理进行的寄存器的类
        std::unique_ptr<registers> registers_;

        //存储所有断点的集合
        stoppoint_collection<breakpoint_site> breakpoint_sites_;

        stoppoint_collection<watchpoint> watchpoints_;
        //设置硬件断点 算是内部实现部分
        int set_hardware_stoppoint(
            virt_addr address, stoppoint_mode mode, std::size_t size);
        
        syscall_catch_policy syscall_catch_policy_ = 
            syscall_catch_policy::catch_none();

        bool expecting_syscall_exit_ = false;
    };
}

#endif