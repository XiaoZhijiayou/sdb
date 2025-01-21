#include <sys/types.h>
#include <signal.h>
#include <fstream>
#include <catch2/catch_test_macros.hpp>
#include <libsdb/process.hpp>
#include <libsdb/error.hpp>
#include <libsdb/pipe.hpp>
#include <libsdb/bit.hpp>

using namespace sdb;

namespace {
    bool process_exists(pid_t pid){
        //通过信号 0 来进行一个“存在性检查”
        auto ret = kill(pid, 0);
        //errno != ESRCH：如果 kill 返回 -1，表示进程不存在或没有权限。
        //在这种情况下，errno 会被设置为 ESRCH，表示没有找到该进程。
        return ret != -1 and errno != ESRCH;
    }

    char get_process_status(pid_t pid){
        std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
        std::string data;
        std::getline(stat,data);
        auto index_of_last_parenthesis = data.rfind(')');
        auto index_of_status_indicator = index_of_last_parenthesis + 2;
        return data[index_of_status_indicator];
    }
}

// 测试是否对文件形式的调试是否可以
TEST_CASE("process::launch success", "[process]"){
    auto proc = process::launch("yes");
    // 检测系统中是否存在该进程
    REQUIRE(process_exists(proc->pid()));
}

//测试对于不存在的文件是否会报错
TEST_CASE("process::launch no such program", "[process]") {
    REQUIRE_THROWS_AS(process::launch("you_do_not_have_to_be_good"), error);
}

// 测试对于
TEST_CASE("process::attach success", "[process]") {
    auto target = process::launch("test/targets/run_endlessly", false);
    auto proc = process::attach(target->pid());
    REQUIRE(get_process_status(target->pid()) == 't');
}

// 测试对于零进程是否可以进行调试
TEST_CASE("process::attach invalid PID", "[process]") {
    REQUIRE_THROWS_AS(process::attach(0), error);
}

TEST_CASE("process::resume success", "[process]") {
    {
        auto proc = process::launch("test/targets/run_endlessly");
        proc->resume();
        auto status = get_process_status(proc->pid());
        auto success = status == 'R' or status == 'S';
        REQUIRE(success);
    }

    {
        auto target = process::launch("test/targets/run_endlessly", false);
        auto proc = process::attach(target->pid());
        proc->resume();
        auto status = get_process_status(proc->pid());
        auto success = status == 'R' or status == 'S';
        REQUIRE(success);
    }
}

TEST_CASE("process::resume already terminated", "[process]") {
    auto proc = process::launch("test/targets/end_immediately");
    proc->resume();
    proc->wait_on_signal();
    REQUIRE_THROWS_AS(proc->resume(), error);
}

TEST_CASE("Write register works", "[register]") {
    bool close_on_exec = false;
    sdb::pipe channel(close_on_exec);

    auto proc = process::launch(
        "test/targets/reg_write", true, channel.get_write()); 
    channel.close_write();
    proc->resume();
    proc->wait_on_signal();
    auto& regs = proc->get_registers();
    regs.write_by_id(register_id::rsi, 0xcafecafe);

    proc->resume();
    proc->wait_on_signal();

    auto output = channel.read();

    REQUIRE(to_string_view(output) == "0xcafecafe");

    regs.write_by_id(register_id::mm0,0xba5eba11);

    proc->resume();
    proc->wait_on_signal();
    
    output = channel.read();
    REQUIRE(to_string_view(output) == "0xba5eba11");

    regs.write_by_id(register_id::xmm0, 42.24);

    proc->resume();
    proc->wait_on_signal();
    
    output = channel.read();
    REQUIRE(to_string_view(output) == "42.24");

}

TEST_CASE("Read register works", "[register]") {
    auto proc = process::launch("test/targets/reg_read");
    auto& regs = proc->get_registers();

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<std::uint64_t>(register_id::r13) ==
        0xcafecafe);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<std::uint8_t>(register_id::r13b) == 42);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<byte64>(register_id::mm0)
        == to_byte64(0xba5eba11ull));

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<byte128>(register_id::xmm0) ==
        to_byte128(64.125));

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<long double>(register_id::st0) ==
        64.125L);
}