#  PhysPuppet

이것이 댕글링 PTE로 이어지는 제가 발견한 첫 번째 취약성이었습니다. 이 보고서에서 설명한 원래의 익스플로잇에서는 SockPuppet에서 영감을 받아 물리 페이지 내에 소켓 관련 객체를 재할당했습니다. 이러한 영감을 준 Ned Williamson에게 감사하며, 그래서 이 이름을 사용했습니다.

## Abbreviations

- KRKW: kernel read/write
- PUAF: physical use-after-free
- VMC: vm_map_copy structure
- VME: vm_map_entry structure
- VMO: vm_object structure
- VMP: vm_page structure
- VMNE: vm_named_entry structure

## Introduction
이 보고서는 XNU 커널의 취약성에 대한 익스플로잇을 제시합니다:

- CVE-2023-23536로 지정됨.
- iOS 16.4 및 macOS 13.3에서 수정됨.
- 앱 샌드박스에서 접근 가능하지만 WebContent 샌드박스에서는 접근 불가.

익스플로잇은 다음 환경에서 성공적으로 테스트됨:

- iOS 16.1 (iPhone 14 Pro Max)
- macOS 13.0 (MacBook Air M2 2022)

아래에 나오는 모든 코드 스니펫은 xnu-8792.41.9에서 가져온 것입니다.

## Part A: From Vulnerability to PUAF
이 익스플로잇의 이 부분은 physpuppet.h에 위치한 physpuppet_run() 함수에서 6단계로 구성되어 있습니다. 각 단계는 아래에서 자세히 설명되며, 각 단계 후의 관련 커널 상태를 보여주는 그림도 포함됩니다. 초록색 박스는 VME를, 노란색 박스는 VMO를, 보라색 박스는 VMC를, 파란색 박스는 VMNE를, 주황색 박스는 VMP를 나타내며, 빨간 텍스트는 이전 그림과의 차이점을 강조합니다. 또한, P는 페이지 크기(즉, 16384 바이트)를 나타냅니다. 마지막으로, 각 단계의 설명을 읽기 전에 physpuppet_run() 함수의 해당 코드를 확인하시기 바랍니다. 코드는 여기서 반복되지 않습니다.

### STEP 1:

MIG 루틴 mach_memory_object_memory_entry_64()는 비정렬된 크기를 가진 이름이 있는 엔트리를 생성할 수 있게 해주는 매우 간단한 루틴입니다. 반환된 이름 있는 엔트리(vmne1)는 비정렬된 크기를 가지고 있지만, 내부 VME(vme1)는 페이지 정렬된 시작 및 끝 주소를 가지고 있습니다. 여기에 MIG 루틴이 따라가는 코드 경로가 있습니다:

```
// Location: osfmk/vm/vm_user.c

kern_return_t
mach_memory_object_memory_entry_64(
    host_t                  host,           // host := mach_host_self()
    boolean_t               internal,       // internal := TRUE
    vm_object_offset_t      size,           // size := 2P+1
    vm_prot_t               permission,     // permission := VM_PROT_DEFAULT
    memory_object_t         pager,          // pager := MEMORY_OBJECT_NULL
    ipc_port_t              *entry_handle)
{
    unsigned int            access;
    vm_named_entry_t        user_entry;
    ipc_port_t              user_handle;
    vm_object_t             object;

    if (host == HOST_NULL) { // branch not taken
        ...
    }

    if (pager == MEMORY_OBJECT_NULL && internal) { // branch taken
        /*
         * Note:
         * - vm_object_allocate() rounds up object->vo_size to 3P.
         * - "object" refers to vmo1 in the figures.
         */
        object = vm_object_allocate(size);
        if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) { // branch taken
            object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
        }
    } else { // branch not taken
        ...
    }
    if (object == VM_OBJECT_NULL) { // branch not taken
        ...
    }

    /*
     * Note:
     * - "user_entry" refers to vmne1 in the figures.
     */
    user_entry = mach_memory_entry_allocate(&user_handle);
    user_entry->size = size;                            // vmne1->size := 2P+1
    user_entry->offset = 0;                             // vmne1->offset := 0P
    user_entry->protection = permission & VM_PROT_ALL;  // vmne1->protection := VM_PROT_DEFAULT
    access = GET_MAP_MEM(permission);
    SET_MAP_MEM(access, user_entry->protection);
    user_entry->is_sub_map = FALSE;

    /*
     * Note:
     * - vm_named_entry_associate_vm_object() will allocate vmc1 and vme1 in the figures.
     * - VME_OBJECT(vme1) will be set to vmo1 and VME_OFFSET(vme1) will be set to 0P.
     * - vme1 will be linked in with vmc1.
     * - vmne1->backing.copy will be set to vmc1.
     */
    vm_named_entry_associate_vm_object(user_entry, object, 0, size,
        (user_entry->protection & VM_PROT_ALL));
    user_entry->internal = object->internal;
    assert(object->internal == internal);
    if (VM_OBJECT_OWNER(object) != TASK_NULL) { // branch not taken
        ...
    }

    *entry_handle = user_handle;
    return KERN_SUCCESS;
}
```

### STEP 2:
이 단계에서는 1단계에서 생성된 이름 있는 엔트리를 매핑하기 위해 vm_map() 루틴을 호출합니다. 그러나 인수는 특이한 엣지 케이스를 유발하도록 조작되어, 비정렬된 크기 1P + 1로 vm_map_enter()를 호출하게 됩니다. 이는 무작위 주소 A에 새로운 VME(vme2)를 생성하고 삽입하지만, 끝 주소는 A + 1P + 1입니다. 여기 vm_map_enter_mem_object_helper()가 따라가는 상세한 코드 경로가 있습니다:
```
// Location: osfmk/vm/vm_map.c

static kern_return_t
vm_map_enter_mem_object_helper(
    vm_map_t                target_map,         // target_map := current_map()
    vm_map_offset_t         *address,           // *address := 0
    vm_map_size_t           initial_size,       // initial_size := ~0ULL
    vm_map_offset_t         mask,               // mask := 0
    int                     flags,              // flags := (VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR)
    vm_map_kernel_flags_t   vmk_flags,          // ...
    vm_tag_t                tag,                // tag := 0
    ipc_port_t              port,               // port := (ipc_port for vmne1)
    vm_object_offset_t      offset,             // offset := 1P
    boolean_t               copy,               // copy := FALSE
    vm_prot_t               cur_protection,     // cur_protection := VM_PROT_DEFAULT
    vm_prot_t               max_protection,     // max_protection := VM_PROT_DEFAULT
    vm_inherit_t            inheritance,        // inheritance := VM_INHERIT_DEFAULT
    upl_page_list_ptr_t     page_list,          // page_list := NULL
    unsigned int            page_list_count)    // page_list_count := 0
{
    vm_map_address_t        map_addr;
    vm_map_size_t           map_size;
    vm_object_t             object;
    vm_object_size_t        size;
    kern_return_t           result;
    boolean_t               mask_cur_protection, mask_max_protection;
    boolean_t               kernel_prefault, try_prefault = (page_list_count != 0);
    vm_map_offset_t         offset_in_mapping = 0;
#if __arm64__
    boolean_t               fourk = vmk_flags.vmkf_fourk; /* fourk := FALSE */
#endif

    if (VM_MAP_PAGE_SHIFT(target_map) < PAGE_SHIFT) { // branch not taken
        ...
    }

    mask_cur_protection = cur_protection & VM_PROT_IS_MASK; // mask_cur_protection := 0
    mask_max_protection = max_protection & VM_PROT_IS_MASK; // mask_max_protection := 0
    cur_protection &= ~VM_PROT_IS_MASK; // cur_protection := VM_PROT_DEFAULT
    max_protection &= ~VM_PROT_IS_MASK; // max_protection := VM_PROT_DEFAULT

    if ((target_map == VM_MAP_NULL) ||
        (cur_protection & ~(VM_PROT_ALL | VM_PROT_ALLEXEC)) ||
        (max_protection & ~(VM_PROT_ALL | VM_PROT_ALLEXEC)) ||
        (inheritance > VM_INHERIT_LAST_VALID) ||
        (try_prefault && (copy || !page_list)) ||
        initial_size == 0) { // branch not taken
        ...
    }

#if __arm64__
    if (cur_protection & VM_PROT_EXECUTE) { // branch not taken
        ...
    }

    if (fourk && VM_MAP_PAGE_SHIFT(target_map) < PAGE_SHIFT) { // branch not taken
        ...
    }
    if (fourk) { // branch not taken
        ...
    } else
#endif
    {
        map_addr = vm_map_trunc_page(*address,
            VM_MAP_PAGE_MASK(target_map)); // map_addr := 0
        map_size = vm_map_round_page(initial_size,
            VM_MAP_PAGE_MASK(target_map)); // map_size := 0
    }
    size = vm_object_round_page(initial_size); // size := 0

    /*
     * Note:
     * - both "map_size" and "size" have been set to 0 because of an integer overflow.
     */

    if (!IP_VALID(port)) { // branch not taken
        ...
    } else if (ip_kotype(port) == IKOT_NAMED_ENTRY) { // branch taken
        vm_named_entry_t        named_entry;
        vm_object_offset_t      data_offset;

        named_entry = mach_memory_entry_from_port(port); // named_entry := vmne1

        if (flags & (VM_FLAGS_RETURN_DATA_ADDR |
            VM_FLAGS_RETURN_4K_DATA_ADDR)) { // branch not taken
            ...
        } else { // branch taken
            data_offset = 0;
        }

        if (size == 0) { // branch taken
            //      1P >= 2P+1
            if (offset >= named_entry->size) { // branch not taken
                ...
            }
            size = named_entry->size - offset; // size := (2P+1)-(1P) = 1P+1
        }
        if (mask_max_protection) { // branch not taken
            ...
        }
        if (mask_cur_protection) { // branch not taken
            ...
        }
        if ((named_entry->protection & max_protection) !=
            max_protection) { // branch not taken
            ...
        }
        if ((named_entry->protection & cur_protection) !=
            cur_protection) { // branch not taken
            ...
        }

        //      1P + 1P+1 < 1P
        if (offset + size < offset) { // branch not taken
            ...
        }
        //               2P+1 < (1P     + 0xffffffffffffffff)
        if (named_entry->size < (offset + initial_size)) { // branch not taken
            ...
        }

        if (named_entry->is_copy) { // branch not taken
            ...
        }

        offset = offset + named_entry->offset; // offset := 1P + 0P = 1P

        /*
         * Note:
         * - "map_size" is set to 1P+1 here, which is what we will pass to vm_map_enter().
         */
        if (!VM_MAP_PAGE_ALIGNED(size,
            VM_MAP_PAGE_MASK(target_map))) { // branch taken
            map_size = size; // map_size := 1P+1
        }

        named_entry_lock(named_entry);
        if (named_entry->is_sub_map) { // branch not taken
            ...
        } else if (named_entry->is_copy) { // branch not taken
            ...
        }

        if (named_entry->is_object) { // branch taken
            ...

            object = vm_named_entry_to_vm_object(named_entry); // object := vmo1
            assert(object != VM_OBJECT_NULL);
            vm_object_lock(object);
            named_entry_unlock(named_entry);

            vm_object_reference_locked(object); // vmo1->ref_count := 2

            ...

            vm_object_unlock(object);
        } else { // branch not taken
            ...
        }
    } else if (ip_kotype(port) == IKOT_MEMORY_OBJECT) { // branch not taken
        ...
    } else { // branch not taken
        ...
    }

    if (object != VM_OBJECT_NULL &&
        object->named && // object->named == FALSE
        object->pager != MEMORY_OBJECT_NULL &&
        object->copy_strategy != MEMORY_OBJECT_COPY_NONE) { // branch not taken
        ...
    }

    if (copy) { // branch not taken because copy == FALSE
        ...
    }

    // kernel_prefault := FALSE
    kernel_prefault = (try_prefault && vm_kernel_map_is_kernel(target_map));
    vmk_flags.vmkf_keep_map_locked = (try_prefault && !kernel_prefault);

#if __arm64__
    if (fourk) { // branch not taken
        ...
    } else
#endif
    {
        /*
         * Note:
         * - We end up calling vm_map_enter() with map_size equal to 1P + 1.
         */
        result = vm_map_enter(
            target_map,             // current_map()
            &map_addr,              // 0
            map_size,               // 1P+1
            (vm_map_offset_t)mask,  // 0
            flags,                  // (VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR)
            vmk_flags,              // ...
            tag,                    // 0
            object,                 // vmo1
            offset,                 // 1P
            copy,                   // FALSE
            cur_protection,         // VM_PROT_DEFAULT
            max_protection,         // VM_PROT_DEFAULT
            inheritance);           // VM_INHERIT_DEFAULT
    }
    if (result != KERN_SUCCESS) { // branch not taken because result == KERN_SUCCESS
        ...
    }


    if (result == KERN_SUCCESS && try_prefault) { // branch not taken because try_prefault == FALSE
        ...
    }

    if (flags & (VM_FLAGS_RETURN_DATA_ADDR |
        VM_FLAGS_RETURN_4K_DATA_ADDR)) { // branch not taken
        ...
    } else { // branch taken
        *address = map_addr; // *address := A
    }
    return result;
}
```

### STEP 3:
단계 2 이후, 우리 VM 맵에 비정렬된 VME(vme2)가 연결되어 있습니다. 단계 3에서는 vme2가 커버하는 두 페이지에 단순히 장애를 일으킵니다. 주소 A + 1P + PAGE_MASK에서 장애가 발생하더라도, vm_fault_internal()은 장애 주소를 A + 1P로 자르기 때문에 vm_map_lookup_and_lock_object()에서 수행하는 조회는 여전히 vme2를 성공적으로 반환합니다. 실제로 조회 루틴은 최종적으로 vm_map_store_lookup_entry_rb()에 도달하게 됩니다. A + 1P는 vme2->vme_start(A)보다 크거나 같고 vme2->vme_end(A + 1P + 1)보다 엄격히 작기 때문에, vme2를 vm_entry out 매개변수로 반환하며 TRUE를 반환합니다. VME_OFFSET(vme2)는 1P와 같으므로, 첫 번째 장애 시 vm_map_lookup_and_lock_object()의 오프셋 out 매개변수는 1P가 되고, 두 번째 장애 시 2P가 됩니다. 다음으로 vm_fault_internal()은 vm_page_lookup()을 호출하며, 이는 vmo1에서 해당 페이지를 찾는 데 실패합니다. 따라서 페이지를 free_list 에서 가져와서 0으로 채워야 합니다. 첫 번째 장애 시, vmp1은 vmo1에 1P 오프셋으로 삽입되며, VM_PAGE_GET_PHYS_PAGE(vmp1)는 읽기 및 쓰기 권한과 함께 가상 주소 A의 PTE에 삽입됩니다. 두 번째 장애 시, vmp2는 vmo1에 2P 오프셋으로 삽입되며, VM_PAGE_GET_PHYS_PAGE(vmp2)는 다시 읽기 및 쓰기 권한과 함께 가상 주소 A + 1P의 PTE에 삽입됩니다.


### STEP 4:
이 단계에서는 vm_deallocate()를 호출하여 vme2가 커버하는 가상 주소 범위를 해제합니다. 이는 vm_map_delete()에 의해 수행됩니다. 아래는 그 함수의 상세 코드 경로입니다:

```
// Location: osfmk/vm/vm_map.c

static kmem_return_t
vm_map_delete(
    vm_map_t                map,        // map := current_map()
    vm_map_offset_t         start,      // start := A
    vm_map_offset_t         end,        // end := A+2P
    vmr_flags_t             flags,      // flags := VM_MAP_REMOVE_NO_FLAGS
    kmem_guard_t            guard,      // guard := KMEM_GUARD_NONE
    vm_map_zap_t            zap_list)
{
    vm_map_entry_t          entry, next;
    int                     interruptible;
    vm_map_offset_t         gap_start = 0;
    vm_map_offset_t         clear_in_transition_end = 0;
    __unused vm_map_offset_t save_start = start;
    __unused vm_map_offset_t save_end = end;
    vm_map_delete_state_t   state = VMDS_NONE;
    kmem_return_t           ret = { };

    if (vm_map_pmap(map) == kernel_pmap) { // branch not taken
        ...
    }

    if (map->terminated || os_ref_get_count_raw(&map->map_refcnt) == 0) { // branch not taken
        ...
    }

    interruptible = (flags & VM_MAP_REMOVE_INTERRUPTIBLE) ?
        THREAD_ABORTSAFE : THREAD_UNINT; // interruptible := THREAD_UNINT

    if ((flags & VM_MAP_REMOVE_NO_MAP_ALIGN) == 0 &&
        (start & VM_MAP_PAGE_MASK(map))) { // branch not taken
        ...
    }

    if ((state & VMDS_GAPS_OK) == 0) { // branch taken
        if (end == 0 || end > vm_map_max(map)) { // branch not taken
            ...
        }

        if (end < start) { // branch not taken
            ...
        }

        if (start < vm_map_min(map)) { // branch not taken
            ...
        }
    } else { // branch not taken
        ...
    }

    // entry := vme2
    while (vm_map_lookup_entry_or_next(map, start, &entry)) {
        if (entry->superpage_size && (start & ~SUPERPAGE_MASK)) { // branch not taken
            ...
        } else { // branch taken
            SAVE_HINT_MAP_WRITE(map, entry->vme_prev);
            break;
        }
    }

    if (entry->superpage_size) { // branch not taken
        ...
    }

    for (vm_map_offset_t s = start; s < end;) { // s := A
        if (state & VMDS_NEEDS_LOOKUP) { // branch not taken
            ...
        }

        if (clear_in_transition_end) { // branch not taken
            ...
        }

        if (entry == vm_map_to_entry(map) || s < entry->vme_start) { // branch not taken
            ...
        }

        if (state & VMDS_KERNEL_PMAP) { // branch not taken
            ...
        }

        if (entry->vme_permanent && entry->is_sub_map) { // branch not taken
            ...
        }

        if (entry->vme_start < s) { // branch not taken
            ...
        }

        if (end < entry->vme_end) { // branch not taken
            ...
        }

        if (entry->vme_permanent && entry->is_sub_map) { // branch not taken
            ...
        }

        assert(s == entry->vme_start);
        assert(entry->vme_end <= end);

        if (entry->in_transition) { // branch not taken
            ...
        }

        if (entry->wired_count) { // branch not taken
            ...
        }

        assert(entry->wired_count == 0);
        assert(entry->user_wired_count == 0);

        if (!entry->vme_permanent) { // branch taken
            /*
             * Typical case: the entry really shouldn't be permanent
             */
        } else if ((flags & VM_MAP_REMOVE_IMMUTABLE_CODE) &&
            (entry->protection & VM_PROT_EXECUTE) &&
            developer_mode_state()) { // branch not taken
            ...
        } else if ((flags & VM_MAP_REMOVE_IMMUTABLE) || map->terminated) { // branch not taken
            ...
        } else { // branch not taken
            ...
        }

        if (entry->is_sub_map) { // branch not taken
            ...
        } else if (entry->vme_kernel_object ||
            VME_OBJECT(entry) == compressor_object) { // branch not taken
            ...
        } else if (map->mapped_in_other_pmaps &&
            os_ref_get_count_raw(&map->map_refcnt) != 0) { // branch not taken
            ...
        } else if ((VME_OBJECT(entry) != VM_OBJECT_NULL) ||
            (state & VMDS_KERNEL_PMAP)) { // branch taken
            /*
             * Note:
             * - pmap_remove_options() is responsible to clear the PTEs covered by this VME.
             */
            pmap_remove_options(map->pmap,  // current_pmap()
                (addr64_t)entry->vme_start, // A
                (addr64_t)entry->vme_end,   // A+1P+1
                PMAP_OPTIONS_REMOVE);
        }

        if (entry->iokit_acct) { // branch not taken
            ...
        }

        s = entry->vme_end; // s := A+1P+1
        next = entry->vme_next;
        ret.kmr_size += entry->vme_end - entry->vme_start;

        if (entry->vme_permanent) { // branch not taken
            ...
        } else { // branch taken
            /*
             * Note:
             * - vme2 is unlinked from the doubly-linked list and red-black tree here.
             */
            vm_map_entry_zap(map, entry, zap_list);
        }

        entry = next;

        ...

        /*
         * Note:
         * - The next VME is outside the unmapped VA range, so we will exit this loop.
         */
    }

    ...

    return ret;
}
```

간단히 말해서, pmap_remove_options()가 vme2의 VA 범위에 대해 호출됩니다. 중요한 점은 이 시점에서 vme2의 끝 주소가 정렬되지 않았다는 것이지만, 불행히도 pmap_remove_options()는 이 조건을 디버그 및 개발 빌드의 MACH_ASSERT 매크로 내에서만 확인합니다. 마지막으로 PPL 루틴 pmap_remove_options_internal()이 호출되지만, 끝 주소의 정렬되지 않은 "페이지 오프셋"이 이동되어 두 개의 PTE 중 첫 번째 것만 지워지게 됩니다. 다음 스니펫에서 이를 확인할 수 있습니다.

```
// Location: osfmk/arm/pmap/pmap.c

MARK_AS_PMAP_TEXT vm_map_address_t
pmap_remove_options_internal(
    pmap_t pmap,            // pmap := current_pmap()
    vm_map_address_t start, // start := A
    vm_map_address_t end,   // end := A+1P+1
    int options)            // options := PMAP_OPTIONS_REMOVE
{
    vm_map_address_t eva = end; // eva := A+1P+1
    pt_entry_t     *bpte, *epte;
    pt_entry_t     *pte_p;
    tt_entry_t     *tte_p;
    int             remove_count = 0;
    bool            need_strong_sync = false;
    bool            unlock = true;

    if (__improbable(end < start)) { // branch not taken
        ...
    }

    validate_pmap_mutable(pmap);

    __unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

    pmap_lock(pmap, PMAP_LOCK_EXCLUSIVE);

    tte_p = pmap_tte(pmap, start); // tte_p := pointer to L2 TTE

    if (tte_p == (tt_entry_t *) NULL) { // branch not taken
        ...
    }

    if ((*tte_p & ARM_TTE_TYPE_MASK) == ARM_TTE_TYPE_TABLE) {
        pte_p = (pt_entry_t *) ttetokv(*tte_p); // pte_p := pointer to L3 TT
        bpte = &pte_p[pte_index(pt_attr, start)]; // bpte := pointer to first PTE
        epte = bpte + ((end - start) >> pt_attr_leaf_shift(pt_attr)); // epte := pointer to second PTE

        /*
         * Note:
         * - The difference of (end - start) is 1P+1, but becomes 1P after being shifted right,
         *   such that the end result is the same as if "end" had simply been A+1P.
         * - Therefore, only the first PTE for virtual address A gets removed.
         */

        if (__improbable((pmap->type != PMAP_TYPE_KERNEL) && (ptep_get_pmap(bpte) != pmap))) {
            ...
        }

        remove_count = pmap_remove_range_options(pmap, start, bpte, epte, &eva,
            &need_strong_sync, options);

        if ((pmap->type == PMAP_TYPE_USER) && (ptep_get_info(pte_p)->refcnt == 0)) {
            ...
        }
    }

done:
    if (unlock) {
        pmap_unlock(pmap, PMAP_LOCK_EXCLUSIVE);
    }

    if (remove_count > 0) {
        PMAP_UPDATE_TLBS(pmap, start, eva, need_strong_sync, true);
    }
    return eva;
}
```

참고로 vm_map_delete()가 반환된 후에는 vm_map_remove_and_unlock()도 호출되어 vm_map_zap_dispose()가 호출됩니다. 이 과정에서 vme2가 해제되고 vmo1의 참조 횟수가 1로 감소합니다.

제 4단계 이후의 관련 커널 상태는 다음과 같습니다:

### STEP 5:
이 단계에서는 step 1에서 반환된 포트, 즉 vmne1에 대한 할당을 해제하기 위해 mach_port_deallocate()를 호출합니다. 이로 인해 명명된 엔트리와 관련된 모든 구조체들이 해제됩니다. 그러나 이 엔트리는 vmo1에 대한 마지막 참조를 가지고 있었기 때문에, 이는 vm_object_reap()을 발생시킵니다. 이 함수는 vmp1과 vmp2를 모두 pmap_disconnect()를 호출하지 않고 자유 리스트에 다시 넣습니다. 그러나 여전히 vmp2에 의해 참조되는 물리 페이지에 대한 덩어리 PTE가 남아 있습니다. 이 단계 이후의 관련 커널 상태는 다음과 같습니다:

### STEP 6:
해당 단계에서는 vm_allocate()를 호출하여 원래 PTE들의 VA 범위를 커버하는 또 다른 VME (vme3)을 생성합니다. 그러나 vme3를 삭제할 때 vm_map_delete()에 표시된 스니펫에서 볼 수 있듯이, VME_OBJECT(vme3)을 null이 아닌 값으로 초기화하는 것이 중요합니다. 이렇게 하지 않으면 vme3이 삭제될 때 pmap_remove_options()가 호출되지 않습니다. 이는 vme3의 첫 번째 페이지를 faulting in하여 쉽게 달성할 수 있습니다. 이는 새로운 객체(vmo2)를 할당하고, 새로운 제로로 채워진 페이지(vmp3)를 채워 넣고, 이 페이지의 물리 주소를 가상 주소 A에 대한 PTE에 입력함으로써 수행됩니다. 물론 우리는 매달리는 PTE를 덮어 쓸 두 번째 페이지를 faulting in하고 싶지 않습니다.

다음은 단계 6 이후의 관련 커널 상태에 대한 그림입니다:

그리고 완성했습니다! 이제 우리는 하나의 물리 페이지에서 안정적인 PUAF(primitive use-after-free) 기법을 가지고 있습니다. 이제 필요한 만큼 이 전체 절차를 반복하여 임의의 수의 PUAF 페이지를 얻을 수 있습니다.

## Part B: From PUAF to KRKW
이 부분은 모든 PUAF 공격에서 공유되는 부분이므로 PUAF 공격에 대한 자세한 내용은 해당 글을 확인해주세요.

## Part C: From KRKW to Cleanup
이 exploit은 커널 상태를 손상시키지 않아서 KRKW 이후에 정리(clean-up)를 필요로 하지 않습니다.
