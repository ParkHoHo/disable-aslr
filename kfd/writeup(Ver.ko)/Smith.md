#  Smith

## Introduction
이 글에서는 XNU 커널의 취약점을 악용하는 방법을 소개합니다.

CVE-2023-32434 가 할당됨 .
iOS 16.5.1 및 macOS 13.4.1에서 수정되었습니다.
WebContent 샌드박스에서 접근이 가능하며 실제로 악용되었을 가능성이 있습니다.
이 CVE가 여러 정수 오버플로를 수정했다는 점에 유의하세요. 따라서 제 익스플로잇에 사용된 정수 오버플로가 야생에서도 사용되었는지 여부는 불분명합니다. 게다가 사용되었다 하더라도 같은 방식으로 익스플로잇되지 않았을 수도 있습니다.
이 익스플로잇은 다음에서 성공적으로 테스트되었습니다.

- iOS 16.3, 16.3.1, 16.4 및 16.5(iPhone 14 Pro Max)
- macOS 13.1 및 13.4(MacBook Air M2 2022)

아래에 표시된 모든 코드 조각은 xnu-8792.81.2 에서 가져온 것입니다 .

## Part A: From Vulnerability to PUAF
이 익스플로잇의 이 부분은 smith.h에 있는 smith_run() 함수에 레이블이 지정된 5단계로 구성되어 있습니다. 각 단계를 자세히 설명하지만, 먼저 각 단계 이후의 관련 커널 상태를 그림으로 보여드리겠습니다. 
녹색 상자는 VME를 나타내고, 노란색 상자는 VMO를 나타내고, 빨간색 텍스트는 이전 단계와 비교한 차이점을 강조합니다.

또한 다음 사항을 참고하십시오.

- 각 단계에 대한 설명을 읽기 전에, smith_run() 함수의 해당 코드를 확인하세요. 여기서는 반복하지 않을 것입니다.
- 각 단계에 대한 설명을 읽은 후 이 이미지로 돌아와서 커널 상태에 대한 이해와 일치하는지 확인하세요.

![smith-figure1.png](/writeups/figures/smith-figure1.png)

### Step 1:
이 단계는 2단계에서 취약점을 트리거하기 전에 수행되며 설정에 부분적으로 책임이 있습니다. 안정성에 중점을 둔 나머지 설정은 부록 A에 자세히 설명되어 있습니다. 여기서는 단순히 위 이미지에서 vme0에서 vme4로 표시된 5개의 인접한 VME를 다음과 같은 속성으로 할당합니다:

- vme0과 vme2의 크기는 1페이지입니다.
- vme1의 크기는 X페이지이며, 여기서 X는 원하는 PUAF 페이지 수이며 최소 2페이지여야 합니다.
- vme3의 크기는 vme1 및 vme2의 크기, 즉 (X+1) 페이지와 같습니다.
- vme4의 크기는 vme0 및 vme3의 크기, 즉 (X+2) 페이지와 같습니다.
- 처음 3개의 VME는 vm_map_enter()에서 vm_object_coalesce()를 피하기 위해 주소가 줄어드는 순서로 할당됩니다.
- 마지막 2개의 VME는 VM_FLAGS_PURGABLE 플래그를 사용하여 복사_전략이 MEMORY_OBJECT_COPY_NONE인 VMO를 소유하도록 초기화됩니다.

선택적으로, 각각 vmo0 및 vmo1을 미리 채우기 위해 vme3 및 vme4의 VA 범위에서 결함을 일으킬 수도 있습니다. 이 방법은 반드시 필요한 것은 아니지만 3단계와 5단계에서 페이지를 제로 채우기(2X+3)하지 않아도 되므로 중요 섹션의 지속 시간을 약간 줄일 수 있습니다.

### Step 2:
상위 수준에서 이 단계는 2개의 하위 단계로 구성됩니다. 하위 단계 2A에서는 vm_map_copyin_internal()에서 취약점을 트리거하여 vme2의 끝을 0으로 자르고 0에서 시작하는 다른 VME(즉, vme2a)도 할당합니다. 그러나 이 시점에서 vm_map_copyin_internal()은 영역 소진 패닉에 도달할 때까지 VME를 계속 할당하는 무한 루프에 진입하게 됩니다. 따라서 vm_copy()를 호출하기 전에 주소 0에서 vm_-protect()를 호출하는 4개의 스레드를 바쁜 루프에서 생성합니다. 이 스레드는 메인 스레드에서 취약점이 트리거될 때까지 아무 작업도 수행하지 않습니다. 하위 단계 2B에서는 vme2a가 VM 맵에 삽입된 후 4개의 스레드 중 하나가 vme2a의 끝을 1P(즉, PAGE_SIZE)로 클립하고 보호를 VM_PROT_WRITE로 변경하며 1P에서 시작하는 또 다른 VME(즉, vme2b)도 할당합니다. 한편 메인 스레드로 돌아가면 vm_map_copyin_internal()은 맵 잠금을 다시 가져와 주소 0에서 vme2a를 조회합니다. 그러나 새로운 보호 기능에 VM_PROT_READ가 누락되어 있으므로 KERN_PROTECTION_FAILURE로 종료됩니다.

다음은 메인 스레드에서 vm_copy()에 의해 호출되는 vm_map_copyin_internal()의 코드 경로에 대한 자세한 설명입니다:
```c
kern_return_t
vm_map_copyin_internal(
    vm_map_t         src_map,  // src_map == current_map()
    vm_map_address_t src_addr, // src_addr == C
    vm_map_size_t    len,      // len == (0ULL-C-1)
    int              flags,    // flags == 0
    vm_map_copy_t    *copy_result)
{
    vm_map_entry_t   tmp_entry;
    vm_map_entry_t   new_entry = VM_MAP_ENTRY_NULL;
    vm_map_offset_t  src_start;
    vm_map_offset_t  src_end;
    vm_map_offset_t  src_base;
    vm_map_t         base_map = src_map;
    boolean_t        map_share = FALSE;
    submap_map_t     *parent_maps = NULL;
    vm_map_copy_t    copy;
    vm_map_address_t copy_addr;
    vm_map_size_t    copy_size;
    boolean_t        src_destroy;
    boolean_t        use_maxprot;
    boolean_t        preserve_purgeable;
    boolean_t        entry_was_shared;
    vm_map_entry_t   saved_src_entry;

    if (flags & ~VM_MAP_COPYIN_ALL_FLAGS) { // branch not taken
        ...
    }

    src_destroy = (flags & VM_MAP_COPYIN_SRC_DESTROY) ? TRUE : FALSE; // src_destroy := FALSE
    use_maxprot = (flags & VM_MAP_COPYIN_USE_MAXPROT) ? TRUE : FALSE; // use_maxprot := FALSE
    preserve_purgeable = (flags & VM_MAP_COPYIN_PRESERVE_PURGEABLE) ? TRUE : FALSE; // preserve_purgeable := FALSE

    if (len == 0) { // branch not taken
        ...
    }

    src_end = src_addr + len; // src_end := (0ULL-1)
    if (src_end < src_addr) { // branch not taken, because no overflow occured at this point
        ...
    }

    /*
     * (0)
     * @note:
     * This trigger the integer overflow that can be considered the "root cause" vulnerability.
     */
    src_start = vm_map_trunc_page(src_addr, VM_MAP_PAGE_MASK(src_map)); // src_start := C
    src_end = vm_map_round_page(src_end, VM_MAP_PAGE_MASK(src_map)); // src_end := 0

    if ((len <= msg_ool_size_small) &&
        (!use_maxprot) &&
        (!preserve_purgeable) &&
        (!(flags & VM_MAP_COPYIN_ENTRY_LIST)) &&
        ((src_start >= vm_map_min(src_map)) &&
         (src_start < vm_map_max(src_map)) &&
         (src_end >= vm_map_min(src_map)) &&
         (src_end < vm_map_max(src_map)))) { // branch not taken, because (len > msg_ool_size_small)
        ...
    }

    copy = vm_map_copy_allocate();
    copy->type = VM_MAP_COPY_ENTRY_LIST;
    copy->cpy_hdr.entries_pageable = TRUE;
    copy->cpy_hdr.page_shift = (uint16_t)(VM_MAP_PAGE_SHIFT(src_map));
    vm_map_store_init(&(copy->cpy_hdr));
    copy->offset = src_addr;
    copy->size = len;

    /*
     * (1)
     * @note:
     * Here, new_entry is initialized with a temporary VME, so it's not NULL.
     */
    new_entry = vm_map_copy_entry_create(copy);

    ...

    vm_map_lock(src_map); // take the map lock

    if (!vm_map_lookup_entry(src_map, src_addr, &tmp_entry)) { // branch not taken, tmp_entry := vme2
        ...
    }

    if (!tmp_entry->is_sub_map) { // branch taken
        vm_map_clip_start(src_map, tmp_entry, src_start); // no clipping because (src_start == tmp_entry->vme_start)
    }

    if (src_start < tmp_entry->vme_start) { // branch not taken, because (src_start == tmp_entry->vme_start)
        ...
    }

    copy_addr = src_start; // copy_addr := C

    while (TRUE) {
        vm_map_entry_t     src_entry = tmp_entry; // src_entry := vme2 (1st iteration); src_entry := vme2a (2nd iteration)
        vm_map_size_t      src_size;
        vm_object_t        src_object;
        vm_object_offset_t src_offset;
        vm_object_t        new_copy_object;
        boolean_t          src_needs_copy;
        boolean_t          new_entry_needs_copy;
        boolean_t          was_wired;
        boolean_t          saved_used_for_jit;
        vm_map_version_t   version;
        kern_return_t      result;

        while (tmp_entry->is_sub_map) { // branch not taken
            ...
        }

        if ((VME_OBJECT(tmp_entry) != VM_OBJECT_NULL) &&
            (VME_OBJECT(tmp_entry)->phys_contiguous)) { // branch not taken
            ...
        }

        /*
         * (2)
         * @note:
         * For the 1st iteration, new_entry is not NULL because it was initialized at (1).
         *
         * (6)
         * @note:
         * For the 2nd iteration, new_entry is NULL because it was updated at (5).
         */
        if (new_entry == VM_MAP_ENTRY_NULL) { // branch not taken for the 1st iteration, but taken for the 2nd iteration
            version.main_timestamp = src_map->timestamp;
            vm_map_unlock(src_map); // release the map lock
            new_entry = vm_map_copy_entry_create(copy);
            vm_map_lock(src_map); // take back the map lock

            /*
             * (7)
             * @note:
             * This timestamp comparison fails because one or more of the 4 spinner threads will have taken the map lock.
             * Also, note that src_start is no longer equal to C, but is now equal to 0 because it was updated at (5).
             */
            if ((version.main_timestamp + 1) != (src_map->timestamp)) { // branch taken
                if (!vm_map_lookup_entry(src_map, src_start, &tmp_entry)) { // branch not taken, tmp_entry := vme2a
                    ...
                }
                if (!tmp_entry->is_sub_map) { // branch taken
                    vm_map_clip_start(src_map, tmp_entry, src_start); // no clipping because (src_start == tmp_entry->vme_start)
                }
                continue;
            }
        }

        /*
         * (3)
         * @note:
         * For the 1st iteration, vme2->protection == VM_PROT_DEFAULT, so the check succeeds.
         *
         * (8)
         * @note:
         * For the 2nd iteration, vme2a->protection == VM_PROT_WRITE, so the check fails.
         * Finally, vm_map_copyin_internal() returns KERN_PROTECTION_FAILURE.
         */
        if ((((src_entry->protection & VM_PROT_READ) == VM_PROT_NONE) && (!use_maxprot)) ||
            ((src_entry->max_protection & VM_PROT_READ) == 0)) { // branch not taken for the 1st iteration, but taken for the 2nd iteration
            RETURN(KERN_PROTECTION_FAILURE);
        }

        /*
         * (4)
         * @note:
         * This clips the end of vme2 to 0, which now has a VA range of [C,0).
         * This also allocates and inserts vme2a, which has a VA range of [0,D).
         */
        vm_map_clip_end(src_map, src_entry, src_end);

        src_size = src_entry->vme_end - src_start; // src_size := (0ULL-C)
        src_object = VME_OBJECT(src_entry); // src_object := NULL
        src_offset = VME_OFFSET(src_entry); // src_offset := 0
        was_wired = (src_entry->wired_count != 0); // was_wired := FALSE

        vm_map_entry_copy(src_map, new_entry, src_entry);

        if (new_entry->is_sub_map) { // branch not taken
            ...
        } else { // branch taken
            ...
            assert(!new_entry->iokit_acct);
            new_entry->use_pmap = TRUE;
        }

RestartCopy:
        if (((src_object == VM_OBJECT_NULL) ||
             ((!was_wired) &&
              (!map_share )&&
              (!tmp_entry->is_shared) &&
              (!((debug4k_no_cow_copyin) && (VM_MAP_PAGE_SHIFT(src_map) < PAGE_SHIFT))))) &&
            (vm_object_copy_quickly(VME_OBJECT(new_entry), src_offset, src_size, &src_needs_copy, &new_entry_needs_copy))) { // branch taken
            new_entry->needs_copy = new_entry_needs_copy;

            if ((src_needs_copy) && (!tmp_entry->needs_copy)) { // branch not taken, because (src_needs_copy == FALSE)
                ...
            }

            goto CopySuccessful;
        }

        ...

CopySuccessful:
        vm_map_copy_entry_link(copy, vm_map_copy_last_entry(copy), new_entry);

        /*
         * (5)
         * @note:
         * Here, src_start is updated to 0 and new_entry is updated to NULL.
         */
        src_base = src_start; // src_base := C
        src_start = new_entry->vme_end; // src_start := 0
        new_entry = VM_MAP_ENTRY_NULL;

        while ((src_start >= src_end) && (src_end != 0)) { // branch not taken, because (src_end == 0)
            ...
        }

        if ((VM_MAP_PAGE_SHIFT(src_map) != PAGE_SHIFT) &&
            (src_start >= src_addr + len) &&
            (src_addr + len != 0)) { // branch not taken
            ...
        }

        if ((src_start >= src_end) && (src_end != 0)) { // branch not taken, because (src_end == 0)
            ...
        }

        tmp_entry = src_entry->vme_next; // tmp_entry := vme2a

        if ((tmp_entry->vme_start != src_start) ||
            (tmp_entry == vm_map_to_entry(src_map))) { // branch not taken... so go back to the top of the while loop
            ...
        }
    }

    ...
}
```

다음은 4개의 스피너 스레드에서 vm_protect()에 의해 호출되는 vm_map_protect()의 코드 경로에 대한 자세한 설명입니다:
```c
kern_return_t
vm_map_protect(
    vm_map_t        map,      // map == current_map()
    vm_map_offset_t start,    // start == 0
    vm_map_offset_t end,      // end == 1P
    vm_prot_t       new_prot, // new_prot == VM_PROT_WRITE
    boolean_t       set_max)  // set_max == FALSE
{
    vm_map_entry_t  current;
    vm_map_offset_t prev;
    vm_map_entry_t  entry;
    vm_prot_t       new_max;
    int             pmap_options = 0;
    kern_return_t   kr;

    if (new_prot & VM_PROT_COPY) { // branch not taken
        ...
    }

    vm_map_lock(map); // take the map lock

    if (start >= map->max_offset) { // branch not taken
        ...
    }

    while (1) {
        /*
         * (0)
         * @note:
         * Before the main thread triggers the vulnerability in vm_map_copyin_internal(),
         * this lookup at address 0 fails and vm_map_protect() returns KERN_INVALID_ADDRESS.
         * However, after the bad clip, the lookup succeeds and entry := vme2a, which has a VA range of [0,D).
         */
        if (!vm_map_lookup_entry(map, start, &entry)) { // branch taken before bad clip, but not taken after
            vm_map_unlock(map);
            return KERN_INVALID_ADDRESS;
        }

        if ((entry->superpage_size) && (start & (SUPERPAGE_SIZE - 1))) { // branch not taken
            ...
        }

        break;
    }

    if (entry->superpage_size) { // branch not taken
        ...
    }

    current = entry; // current := vme2a
    prev = current->vme_start; // prev := 0

    while ((current != vm_map_to_entry(map)) && (current->vme_start < end)) { // branch taken (1 iteration)
        if (current->vme_start != prev) { // branch not taken
            ...
        }

        new_max = current->max_protection; // new_max := VM_PROT_ALL

        if ((new_prot & new_max) != new_prot) { // branch not taken
            ...
        }

        if ((current->used_for_jit) &&
            (pmap_has_prot_policy(map->pmap, current->translated_allow_execute, current->protection))) { // branch not taken
            ...
        }

        if (current->used_for_tpro) { // branch not taken
            ...
        }


        if ((new_prot & VM_PROT_WRITE) &&
            (new_prot & VM_PROT_ALLEXEC) &&
            ...
            (!(current->used_for_jit))) { // branch not taken
            ...
        }

        if (map->map_disallow_new_exec == TRUE) { // branch not taken
            ...
        }

        prev = current->vme_end; // prev := D
        current = current->vme_next; // current := vme3, which has a VA range of [D,E)... so exit the while loop
    }

    if ((end > prev) &&
        (end == vm_map_round_page(prev, VM_MAP_PAGE_MASK(map)))) { // branch not taken, because (end < prev)
        ...
    }

    if (end > prev) { // branch not taken, because (end < prev)
        ...
    }

    current = entry; // current := vme2a

    if (current != vm_map_to_entry(map)) { // branch taken
        vm_map_clip_start(map, current, start); // no clipping because (start == current->vme_start)
    }

    while ((current != vm_map_to_entry(map)) && (current->vme_start < end)) { // branch taken (1 iteration)
        vm_prot_t old_prot;

        /*
         * (1)
         * @note:
         * This clips the end of vme2a to 1P, which now has a VA range of [0,1P).
         * This also allocates and inserts vme2b, which has a VA range of [1P,D).
         */
        vm_map_clip_end(map, current, end);

        if (current->is_sub_map) { // branch not taken
            ...
        }

        old_prot = current->protection; // old_prot := VM_PROT_DEFAULT

        if (set_max) { // branch not taken
            ...
        } else {
            current->protection = new_prot; // vme2a->protection := VM_PROT_WRITE
        }

        if (current->protection != old_prot) { // branch taken
            vm_prot_t prot;

            prot = current->protection; // prot := VM_PROT_WRITE
            if ((current->is_sub_map) ||
                (VME_OBJECT(current) == NULL) ||
                (VME_OBJECT(current) != compressor_object)) { // branch taken
                prot &= ~VM_PROT_WRITE; // prot := VM_PROT_NONE
            } else {
                ...
            }

            if (override_nx(map, VME_ALIAS(current)) && (prot)) { // branch not taken
                ...
            }

            if (pmap_has_prot_policy(map->pmap, current->translated_allow_execute, prot)) { // branch not taken
                ...
            }

            if ((current->is_sub_map) && (current->use_pmap)) { // branch not taken
                ...
            } else {
                /*
                 * (2)
                 * @note:
                 * This calls pmap_protect_options() in the VA range [0,1P) with prot == VM_PROT_NONE, which does nothing.
                 *
                 * [STEP 4]
                 * @note
                 * When we restore the protection to VM_PROT_DEFAULT in STEP 4, it will call
                 * pmap_protect_options() in the VA range [0,1P) with prot == VM_PROT_READ, which also does nothing.
                 */
                pmap_protect_options(map->pmap, current->vme_start, current->vme_end, prot, pmap_options, NULL);
            }
        }

        current = current->vme_next; // current := vme2b, which has a VA range of [1P,D)... so exit the while loop
    }

    current = entry; // current := vme2a

    while ((current != vm_map_to_entry(map)) && (current->vme_start <= end)) { // branch taken (2 iterations)
        vm_map_simplify_entry(map, current); // no simplifying, because of different protections
        current = current->vme_next; // current := vme2b for 1st iteration (VA range is [1P,D) so continue); current := vme3 for the 2nd iteration (VA range is [D,E) so break)
    }

    vm_map_unlock(map); // release the map lock
    return KERN_SUCCESS;
}

```

### Step 3:
높은 수준에서 이 단계는 vme3에서 (X+1) 페이지의 복사본을 만들고, 먼저 vmo0에 0으로 채워진 다음 vme1부터 삽입합니다. vmo0의 복사 전략이 MEMORY_OBJECT_COPY_NONE이므로 vm_copy()의 vm_map_copyin() 부분에서 쓰기 시 복사 최적화가 적용되지 않는다는 점에 유의하세요. 대신, vm_object_copy_slowly()에서 복사된 (X+1)개의 페이지를 보유하기 위해 새 VMO(즉, vmo2)가 할당됩니다. vm_map_copyin()이 반환되면 VMC에는 해당 시점에 vmo2에 대한 유일한 참조를 소유하는 단일 VME가 포함됩니다. 그런 다음 vm_copy()는 vm_map_copy_overwrite()를 호출하고, 이 호출은 다시 vm_map_copy_overwrite_nested()를 호출하고, 마지막으로 vm_map_copy_overwrite_aligned()를 호출합니다. 여기서 위 이미지와 같이 vmo2가 임시 VMC에서 이동되어 vme1과 vme2 간에 공유됩니다. vm_copy()가 반환되면 vmo2에는 (X+1)개의 상주 페이지가 포함되어 있지만 그 중 어느 것도 매핑되지 않은 상태입니다. 따라서 memset()을 호출하여 vmo2의 첫 번째 X 페이지의 물리적 주소를 [B,C) VA 범위의 PTE에 입력합니다.

다음은 vm_map_copy_overwrite_aligned()의 코드 경로에 대한 자세한 설명입니다:
```c
static kern_return_t
vm_map_copy_overwrite_aligned(
    vm_map_t        dst_map,   // dst_map == current_map()
    vm_map_entry_t  tmp_entry, // tmp_entry == vme1
    vm_map_copy_t   copy,      // copy == temporary vm_map_copy structure with a single VME that owns vmo2
    vm_map_offset_t start,     // start == B
    __unused pmap_t pmap)
{
    vm_object_t    object;
    vm_map_entry_t copy_entry;
    vm_map_size_t  copy_size;
    vm_map_size_t  size;
    vm_map_entry_t entry;

    /*
     * (0)
     * @note:
     * Although the copy has a single VME initially, it will soon be clipped, which will create and
     * insert a second VME into the copy. Therefore, there will be 2 iterations of this while loop.
     */
    while ((copy_entry = vm_map_copy_first_entry(copy)) != vm_map_copy_to_entry(copy)) {
        /*
         * (1)
         * @note:
         * 1st iteration: copy_size := (X+1)P
         * 2nd iteration: copy_size := 1P
         */
        copy_size = (copy_entry->vme_end - copy_entry->vme_start);

        /*
         * (2)
         * @note:
         * 1st iteration: entry := vme1, with a VA range of [B,C)
         * 2nd iteration: entry := vme2, with a VA range of [C,0)
         */
        entry = tmp_entry;

        if (entry->is_sub_map) { // branch not taken
            ...
        }

        if (entry == vm_map_to_entry(dst_map)) { // branch not taken
            ...
        }

        /*
         * (3)
         * @note:
         * 1st iteration: size := XP
         * 2nd iteration: size := (0ULL-C)
         */
        size = (entry->vme_end - entry->vme_start);

        if ((entry->vme_start != start) || ((entry->is_sub_map) && !entry->needs_copy)) { // branch not taken
            ...
        }

        assert(entry != vm_map_to_entry(dst_map));

        if (!(entry->protection & VM_PROT_WRITE)) { // branch not taken
            ...
        }

        if (!vm_map_entry_is_overwritable(dst_map, entry)) { // branch not taken
            ...
        }

        if (copy_size < size) { // branch taken only for 2nd iteration
            if (entry->map_aligned &&
                !VM_MAP_PAGE_ALIGNED(entry->vme_start + copy_size, VM_MAP_PAGE_MASK(dst_map))) {  // branch not taken
                ...
            }

            /*
             * (4b)
             * @note:
             * No clipping because entry->vme_start + copy_size is greater than entry->vme_end (C+1P > 0).
             */
            vm_map_clip_end(dst_map, entry, entry->vme_start + copy_size);
            size = copy_size; // size = 1P
        }

        if (size < copy_size) { // branch taken only for 1st iteration
            /*
             * (4a)
             * @note:
             * Here, the single VME with a size of (X+1)P in the copy is split into two VMEs.
             * The first one has a size of XP, and the second one has a size of 1P.
             */
            vm_map_copy_clip_end(copy, copy_entry, copy_entry->vme_start + size);
            copy_size = size; // copy_size = XP
        }

        assert((entry->vme_end - entry->vme_start) == size);
        assert((tmp_entry->vme_end - tmp_entry->vme_start) == size);
        assert((copy_entry->vme_end - copy_entry->vme_start) == size);

        object = VME_OBJECT(entry); // object := NULL for both iterations

        if (((!entry->is_shared) &&
             ((object == VM_OBJECT_NULL) || (object->internal && !object->true_share))) ||
            (entry->needs_copy)) { // branch taken for both iterations
            vm_object_t        old_object = VME_OBJECT(entry); // old_object := NULL for both iterations
            vm_object_offset_t old_offset = VME_OFFSET(entry); // old_offset := 0 for both iterations
            vm_object_offset_t offset;

            if ((old_object == VME_OBJECT(copy_entry)) &&
                (old_offset == VME_OFFSET(copy_entry))) { // branch not taken
                ...
            }

            if ((dst_map->pmap != kernel_pmap) &&
                (VME_ALIAS(entry) >= VM_MEMORY_MALLOC) &&
                (VME_ALIAS(entry) <= VM_MEMORY_MALLOC_MEDIUM)) { // branch not taken
                ...
            }

            /*
             * [STEP 5] --> Only read this when you are at STEP 5, otherwise skip this branch.
             * @note:
             * This branch is not taken for both iterations in STEP 3.
             * However, in STEP 5, we also call vm_copy() to repeat the same process,
             * but that time, old_object will be vmo2 during the 2nd iteration.
             */
            if (old_object != VM_OBJECT_NULL) { // branch not taken for STEP 3, but taken for the 2nd iteration of STEP 5
                assert(!entry->vme_permanent);
                if (entry->is_sub_map) {
                    ...
                } else {
                    if (dst_map->mapped_in_other_pmaps) {
                        ...
                    } else {
                        /*
                         * [STEP 5]
                         * @note:
                         * During the 2nd iteration of STEP 5, entry == vme2, which has a VA range of [B,0) at that point.
                         * Therefore, we call pmap_remove_options() on the VA range of [B,0),
                         * which does nothing because end is smaller than start.
                         */
                        pmap_remove_options(
                            dst_map->pmap,
                            (addr64_t)(entry->vme_start),
                            (addr64_t)(entry->vme_end),
                            PMAP_OPTIONS_REMOVE
                        );
                    }

                    /*
                     * [STEP 5]
                     * @note:
                     * During the 2nd iteration of STEP 5, we deallocate the last reference to vmo2 here,
                     * which then calls vm_object_reap(). The pages of vmo2, which we are still pmapped in the
                     * VA range [B,C), are released at the end of the free list without calling pmap_disconnect().
                     */
                    vm_object_deallocate(old_object);
                }
            }

            if (entry->iokit_acct) {  // branch not taken
                ...
            } else { // branch taken
                entry->use_pmap = TRUE;
            }

            assert(!entry->vme_permanent);

            /*
             * (5)
             * @note:
             * 1st iteration: VME_OBJECT(vme1) := vmo2, VME_OFFSET(vme1) := 0
             * 2nd iteration: VME_OBJECT(vme2) := vmo2, VME_OFFSET(vme2) := XP
             */
            VME_OBJECT_SET(entry, VME_OBJECT(copy_entry), false, 0);
            object = VME_OBJECT(entry);
            entry->needs_copy = copy_entry->needs_copy;
            entry->wired_count = 0;
            entry->user_wired_count = 0;
            offset = VME_OFFSET(copy_entry);
            VME_OFFSET_SET(entry, offset);

            vm_map_copy_entry_unlink(copy, copy_entry);
            vm_map_copy_entry_dispose(copy_entry);

            /*
             * (6)
             * @note:
             * 1st iteration: start := C, tmp_entry := vme2
             * 2nd iteration: start := 0, tmp_entry := vme2a (but we exit the while loop because no more VMEs in the copy)
             */
            start = tmp_entry->vme_end;
            tmp_entry = tmp_entry->vme_next;

        } else { // branch not taken
            ...
        }
    }

    return KERN_SUCCESS;
}
```

### Step 4:
이 단계에서는 vme2a와 vme2b 외에도 vme1과 vme2를 “단순화”합니다. 3단계에서 memset()을 호출하기 전에 vm_copy()를 호출하는 번거로움을 감수한 이유는 이 단계에서 해당 VME를 단순화하기 위해 vme1과 vme2가 동일한 VMO를 공유해야 하기 때문입니다. 단순히 memset()을 호출했다면 vme1의 VA 범위인 [B,C)에 있는 PTE도 성공적으로 입력했을 것이지만 vme2와 VMO를 공유하지는 않았을 것입니다. vm_map_protect()의 코드는 이미 2단계에서 설명했으므로 여기서는 반복하지 않겠습니다. 요컨대, vme2a의 보호는 VM_PROT_DEFAULT로 복원됩니다(즉, 4개의 스피너 스레드 중 하나에 의해 VM_PROT_WRITE로 변경되었다는 것을 기억하세요). 마지막으로, 마지막 동안 루프에서 vm_map_simplify_entry()가 두 번 성공적으로 호출됩니다. 첫 번째는 앞의 vme1을 통해 단순화된 vme2를 사용합니다. 그리고 두 번째는 앞의 vme2a로 단순화된 vme2b를 사용합니다.

다음은 vme2를 사용한 vm_map_simplify_entry()의 코드 경로에 대한 자세한 설명입니다:

```c
void
vm_map_simplify_entry(
    vm_map_t       map,        // map == current_map()
    vm_map_entry_t this_entry) // this_entry == vme2
{
    vm_map_entry_t prev_entry;

    prev_entry = this_entry->vme_prev; // prev_entry := vme1

    /*
     * @note:
     * All conditions are satisfied to simplify vme1 and vme2.
     */
    if ((this_entry != vm_map_to_entry(map)) &&
        (prev_entry != vm_map_to_entry(map)) &&
        (prev_entry->vme_end == this_entry->vme_start) &&
        (prev_entry->is_sub_map == this_entry->is_sub_map) &&
        (prev_entry->vme_object_value == this_entry->vme_object_value) &&
        (prev_entry->vme_kernel_object == this_entry->vme_kernel_object) &&
        ((VME_OFFSET(prev_entry) + (prev_entry->vme_end - prev_entry->vme_start)) == VME_OFFSET(this_entry)) &&
        (prev_entry->behavior == this_entry->behavior) &&
        (prev_entry->needs_copy == this_entry->needs_copy) &&
        (prev_entry->protection == this_entry->protection) &&
        (prev_entry->max_protection == this_entry->max_protection) &&
        (prev_entry->inheritance == this_entry->inheritance) &&
        (prev_entry->use_pmap == this_entry->use_pmap) &&
        (VME_ALIAS(prev_entry) == VME_ALIAS(this_entry)) &&
        (prev_entry->no_cache == this_entry->no_cache) &&
        (prev_entry->vme_permanent == this_entry->vme_permanent) &&
        (prev_entry->map_aligned == this_entry->map_aligned) &&
        (prev_entry->zero_wired_pages == this_entry->zero_wired_pages) &&
        (prev_entry->used_for_jit == this_entry->used_for_jit) &&
        (prev_entry->pmap_cs_associated == this_entry->pmap_cs_associated) &&
        (prev_entry->iokit_acct == this_entry->iokit_acct) &&
        (prev_entry->vme_resilient_codesign == this_entry->vme_resilient_codesign) &&
        (prev_entry->vme_resilient_media == this_entry->vme_resilient_media) &&
        (prev_entry->vme_no_copy_on_read == this_entry->vme_no_copy_on_read) &&
        (prev_entry->wired_count == this_entry->wired_count) &&
        (prev_entry->user_wired_count == this_entry->user_wired_count) &&
        (prev_entry->vme_atomic == FALSE) &&
        (this_entry->vme_atomic == FALSE) &&
        (prev_entry->in_transition == FALSE) &&
        (this_entry->in_transition == FALSE) &&
        (prev_entry->needs_wakeup == FALSE) &&
        (this_entry->needs_wakeup == FALSE) &&
        (prev_entry->is_shared == this_entry->is_shared) &&
        (prev_entry->superpage_size == FALSE) &&
        (this_entry->superpage_size == FALSE)) { // branch taken
        if (prev_entry->vme_permanent) { // branch not taken
            ...
        }

        vm_map_store_entry_unlink(map, prev_entry, true); // vme1 is unlinked

        this_entry->vme_start = prev_entry->vme_start; // vme2->vme_start := B
        VME_OFFSET_SET(this_entry, VME_OFFSET(prev_entry)); // VME_OFFSET(vme2) := 0

        if (map->holelistenabled) { // branch taken
            vm_map_store_update_first_free(map, this_entry, TRUE);
        }

        if (prev_entry->is_sub_map) { // branch not taken
            ...
        } else {
            vm_object_deallocate(VME_OBJECT(prev_entry)); // vmo2->ref_count := 1
        }

        vm_map_entry_dispose(prev_entry); // vme1 is deallocated
        SAVE_HINT_MAP_WRITE(map, this_entry); // map->hint := vme2
    }
}
```

### Step 5:
이 단계는 기본적으로 3단계와 동일한 과정을 반복합니다. 높은 수준에서 보면 vme4에서 (X+2) 페이지의 복사본을 만들고, 이 복사본이 먼저 채워져 vmo1에 0으로 채워진 다음 vme0부터 삽입합니다. 다시 한 번, vmo1의 copy_strategy가 MEMORY_OBJECT_COPY_NONE이므로 vm_copy()의 vm_map_copyin() 부분에서 쓰기 시 최적화가 적용되지 않는다는 점에 유의하세요. 대신, 새 VMO(예: vmo3)가 할당되어 vm_object_copy_slowly()에 복사된 (X+2)개의 페이지를 보유합니다. vm_map_copyin()이 반환되면 VMC에는 해당 시점에 vmo3에 대한 유일한 참조를 소유하는 단일 VME가 포함됩니다. 그런 다음 vm_copy()는 vm_map_copy_overwrite()를 호출하고, 이 호출은 다시 vm_map_copy_overwrite_nested()를 호출하며, 마지막으로 vm_map_copy_overwrite_aligned()를 호출합니다. 여기서 위 이미지와 같이 vmo3가 임시 VMC에서 이동되어 vme0와 vme2 간에 공유됩니다.

3단계에서 vm_map_copy_overwrite_aligned()가 vme2를 vme1과 vme2에 삽입할 때, 이 두 VME에는 이전에 연결된 VMO가 없었습니다. 그러나 여기서 5단계에서 동일한 함수가 vme3을 vme0과 vme2에 삽입할 때(즉, 4단계에서 vme1이 할당 해제되었음을 기억하세요), 이전에는 vme0에만 연결된 VMO가 없었습니다. 이와는 대조적으로 vme2에는 [B,C)의 VA 범위에 매핑한 X 페이지를 포함하는 vmo2에 대한 유일한 참조가 있습니다. 3단계의 vm_map_copy_overwrite_aligned()에 대한 코드 스니펫에는 [STEP 5]로 주석이 달린 추가 설명이 있어 어떤 일이 발생하는지 설명합니다. 간단히 말해, 덮어쓰는 VME의 VA 범위(vme2의 경우 [B,0))에 대해 pmap_remove_options()가 호출됩니다. 그러나 끝 주소가 시작 주소보다 작기 때문에 이 함수는 아무 소용이 없습니다. 마지막으로 vm_object_deallocate()를 호출하여 vmo2의 마지막 참조를 해제합니다. 그러면 vm_object_reap()이 트리거되어 pmap_disconnect()를 호출하지 않고도 vmo2의 모든 페이지를 사용 가능한 목록에 다시 넣습니다. 즉, VA 범위의 [B,C) PTE는 여전히 읽기 및 쓰기 권한이 모두 있는 해당 페이지 중 X를 가리킵니다.

다음은 pmap_remove_options()의 코드 경로에 대한 자세한 설명입니다:

```c
void
pmap_remove_options(
    pmap_t           pmap,    // pmap == current_pmap()
    vm_map_address_t start,   // start == B
    vm_map_address_t end,     // end == 0
    int              options) // options == PMAP_OPTIONS_REMOVE
{
    vm_map_address_t va;

    if (pmap == PMAP_NULL) { // branch not taken
        return;
    }

    __unused const pt_attr_t * const pt_attr = pmap_get_pt_attr(pmap);

#if MACH_ASSERT
    if ((start | end) & pt_attr_leaf_offmask(pt_attr)) {
        panic("pmap_remove_options() pmap %p start 0x%llx end 0x%llx",
            pmap, (uint64_t)start, (uint64_t)end);
    }
    if ((end < start) || (start < pmap->min) || (end > pmap->max)) { // only for DEBUG and DEVELOPMENT builds
        panic("pmap_remove_options(): invalid address range, pmap=%p, start=0x%llx, end=0x%llx",
            pmap, (uint64_t)start, (uint64_t)end);
    }
#endif

    if ((end - start) > (pt_attr_page_size(pt_attr) * PAGE_RATIO)) { // branch taken
        pmap_verify_preemptible();
    }

    va = start; // va := B
    while (va < end) { // branch not taken, because (va > end)
        ...
    }
}
```
## Part B: From PUAF to KRKW
이 익스플로잇의 부분은 모든 PUAF 익스플로잇에서 공유되므로 자세한 내용은 PUAF 익스플로잇에 대한 글을 확인하시기 바랍니다.

## Part C: From KRKW to Cleanup
안타깝게도 이 익스플로잇은 VM 맵에 원치 않는 부작용을 일으켜 프로세스가 특정 VM 작업을 수행할 때 또는 프로세스가 종료될 때 커널 패닉을 유발합니다(해결하지 않고 방치할 경우). 5단계가 끝날 때 관찰할 수 있는 한 가지 명백한 부작용은 반전된 VME가 남는다는 것입니다. 실제로 vme2의 VA 범위는 [B,0)입니다. 이를 수정하지 않으면 VM 맵을 삭제하는 동안 “삭제할 항목 없음” 패닉이 발생합니다. 그러나 수정해야 할 부작용이 훨씬 더 많습니다. 눈치 빠른 독자라면 이 익스플로잇이 빨간색-검은색 트리와 구멍 목록에 미치는 영향이 누락된 것을 눈치챘을 것입니다. 이 글의 이 부분은 이러한 모든 부작용을 자세히 설명하기 위한 것이며, 이를 수정하는 방법은 smith_helper_cleanup() 함수에서 수행됩니다.

![smith-figure2.png](/writeups/figures/smith-figure2.png)

#### Cleaning Up the Doubly-Linked List of VMEs
5단계 마지막에 이중 링크된 리스트의 상태는 파트 A의 이미지에서 명확해야 합니다. vme2b를 유출하고 vme2의 끝 주소를 D로 패치하여 VA 범위가 [B,0)가 아닌 [B,D)]가 되도록 수정합니다. 이를 위해서는 세 번의 64비트 쓰기(하나는 vme3의 vme_prev 포인터를 변경하는 데, 하나는 vme2의 vme_next 포인터를 변경하는 데, 하나는 vme2의 vme_end 주소를 변경하는 데)가 필요하다는 점에 유의하세요. 또한 이중으로 연결된 VME 목록의 예측 가능하고 정렬된 특성으로 인해 정리 절차의 이 부분은 완전히 결정론적이라는 점에 유의하시기 바랍니다.

다음은 해당 절차에 대한 그림입니다:

#### Cleaning Up the Red-Black Tree of VMEs
2단계에서 취약점을 트리거하기 전에는 레드-블랙 트리의 상태가 양호합니다. 그러나 2A 단계에서 vm_map_copyin_internal()에서 불량 클립을 트리거하면 VA 범위가 [0,D)인 vme2a를 레드-블랙 트리에 할당하여 삽입합니다. 시작 주소가 0이므로 트리의 가장 왼쪽 노드로 삽입됩니다. 다음으로, 하위 단계 2B에서 vm_map_protect()에서 다른 클립을 트리거하면, vme2a의 VA 범위를 [0,1P)로 업데이트한 후 VA 범위가 [1P,D)인 vme2b를 빨간색-검정색 트리에 할당하여 삽입합니다. 시작 주소가 1P이므로 트리에서 가장 왼쪽 두 번째 노드로 삽입됩니다. 마지막으로 4단계에서 vm_map_simplify_entry()를 통해 빨간색-검정색 트리에서 vme2a의 연결이 해제됩니다.

이 익스플로잇을 수없이 실행해 보았고, 빨간색-검정색 트리의 초기 상태를 무작위화하기 위해 VM_FLAGS_RANDOM_ADDR로 최대 256개의 VME를 할당해 보았지만 아래 이미지와 다른 결과를 본 적이 없습니다. 제가 아는 한, 재조정 가능성이 있기 때문에 항상 그렇게 될 것이라는 수학적인 보장은 없습니다. 유일한 다른 가능성은 vme2b가 왼쪽 하단에 있는 리프 노드(즉, 왼쪽과 오른쪽 자식이 모두 NULL인 경우)인데, 그렇지 않으면 트리가 빨간색-검정색 트리의 조건을 존중하지 않을 것이라고 생각하기 때문입니다. 어쨌든 다른 결과가 발생하면 커널 읽기 프리미티브로 쉽게 감지하고 다른 패치 방법을 사용할 수 있으므로 정리 절차가 여전히 결정론적으로 끝날 것입니다. 현재로서는 vme2b를 유출하여 레드-블랙 트리를 다시 한 번 수정합니다. 여기에는 두 개의 64비트 쓰기만 필요합니다. 하나는 이중 링크된 목록에서 첫 번째 VME(즉, 익스플로잇 시작 전에 VA 범위가 가장 낮았던 VME)의 rbe_parent 포인터를 변경하는 것이고, 하나는 두 번째 VME의 rbe_left 포인터를 변경하는 것입니다.

다음은 해당 절차에 대한 그림입니다:
![smith-figure3.png](/writeups/figures/smith-figure3.png)

### Cleaning Up the Hole List
2단계에서 취약점을 트리거하기 전에는 홀 목록의 상태가 양호합니다. vm_map_copyin_internal()에서 잘못된 클립을 트리거하고 vm_map_protect()에서도 클립이 영향을 미치지 않아야 하므로 홀 목록은 변경되지 않은 상태로 유지됩니다. 안타깝게도 vm_map_simplify_entry()는 변경할 필요가 없는데도 구멍 목록을 변경합니다. 첫 번째 단순화에 성공하면 연결이 해제되는 VME(VA 범위가 [B,C)인 vme1)에서 update_holes_on_entry_deletion()이 호출됩니다. 이렇게 하면 vm_deallocate()로 해당 VA 범위를 할당 해제하는 것처럼 홀 목록에 VA 범위가 [B,C)인 새 홀이 생성됩니다. 그러나 이제 확장 중인 VME인 vme2에서 update_holes_on_entry_creation()이 호출되며, 이제 VA 범위는 [B,0)이 됩니다. 이렇게 하면 방금 생성한 홀이 삭제되지는 않지만 실제로는 기존 첫 번째 홀 바로 뒤에 다른 홀이 생성되고 이 첫 번째 홀의 끝 주소가 손상됩니다. 두 번째 단순화에 성공하면 update_holes_on_entry_deletion()을 통해 구멍 목록의 맨 처음에 또 다른 구멍이 일시적으로 생성되고, update_holes_on_entry_creation()을 통해 즉시 삭제되므로 구멍 목록의 최종 상태는 첫 번째 단순화 후와 완전히 동일해집니다. 불필요하게 생성된 두 개의 홀을 모두 누출하고 첫 번째 홀의 끝 주소를 복원하여 홀 목록을 수정합니다. 따라서 5번의 64비트 쓰기 후에 홀 리스트는 다시 양호한 상태로 돌아옵니다.

이 정리 절차는 주소 A(즉, vme0의 시작 주소) 앞에 최소 2개의 홀이 있는 한 완전히 결정론적이라는 점에 유의하세요. 또한 주소 F(즉, vme4의 끝 주소) 뒤에 구멍이 있는지 여부는 중요하지 않습니다. 물론, [A,F)의 VA 범위는 5개의 VME에 의해 할당되었기 때문에 홀 목록에 포함되지 않도록 보장됩니다. 부록 A의 뒷부분에 설명된 것처럼 5개의 VME를 VM 맵의 끝(즉, 맵->최대 오프셋)에 할당하려고 합니다. 따라서 이러한 요구 사항은 충족하기 쉽습니다. 만약 주소 A 앞에 구멍이 하나만 있다면 아래 이미지의 “새 구멍 0”과 “새 구멍 1”은 단순히 서로 바로 옆에 위치하게 됩니다. 이 경우에도 약간의 조정을 통해 홀 목록을 결정론적으로 정리할 수 있습니다. 물론 익스플로잇을 시작하기 전에 주소 A 앞에 다른 홀을 수동으로 생성하는 것이 훨씬 더 쉬울 것입니다.

업데이트_홀스_온_입력_삭제() 및 업데이트_홀스_온_입력_생성() 호출 후 홀 목록의 중간 상태를 포함한 해당 절차의 그림은 다음과 같습니다:
![smith-figure4.png](/writeups/figures/smith-figure4.png)

#### Cleaning Up the VM Map Metadata
마지막으로 _vm_map 구조의 관련 메타데이터를 패치해야 합니다. 우선, vme2b가 유출되었으므로 map->hdr.nentries를 하나씩 줄여야 합니다. 제가 아는 한, 이것은 패닉 안전에 꼭 필요한 것은 아니지만 만일을 대비하여 패치를 적용하고 싶습니다. 둘째, 유출된 VME를 가리키고 있을 경우를 대비해 map->hint도 업데이트해야 합니다. 스포일러 경고: 두 번째 단순화에 성공하는 동안 힌트가 vme2b로 업데이트되었기 때문입니다. 마지막으로, 두 개의 구멍도 유출되었으므로 그 중 하나를 가리키고 있을 경우를 대비하여 map->hole_hint를 업데이트해야 합니다. 실제로는 구멍 힌트가 이미 첫 번째 구멍을 가리키고 있을 것이므로 이 작업은 필요하지 않습니다. 따라서 메타데이터를 정리하려면 최대 3개의 64비트 쓰기가 필요합니다.

#### Cleaning Up Synchronization: To Lock Or Not To Lock?
맵 잠금을 사용하지 않고 커널 쓰기 프리미티브를 사용하여 VM 맵을 변경하기 때문에 이 전체 정리 절차가 복잡하다는 것을 눈치채셨을 것입니다. 그러나 패치를 적용하기 전에 64비트 쓰기 한 번으로 맵 잠금을 설정할 수 있는 방법이 있습니다. 매개변수 take_vm_map_lock이 켜져 있으면 자체 스레드에서 실행되는 smith_helper_cleanup_pthread() 함수에서 이 작업을 수행합니다. 간단히 말해, 이 스폰된 스레드에서 오른쪽 자식이 자신을 가리키도록 VME를 패치합니다. 그런 다음 vm_-protect()를 호출하여 방금 패치한 VME의 오른쪽에 있는 VA 범위에 대한 보호를 업데이트합니다. 이렇게 하면 vm_map_lookup_entry() 중에 vm_map_protect()가 맵 잠금을 취하고 해당 VME의 오른쪽 자식에서 회전합니다. 한편 메인 스레드로 돌아가서 위에서 설명한 대로 모든 부작용을 안전하게 수정할 수 있습니다. 그리고 작업이 완료되면 스핀온 중인 VME의 원래 오른쪽 자식 값을 복원할 수 있습니다. 해당 쓰기가 원자적인 것이 아니더라도 결국에는 회전하는 스레드에 의해 관찰되어 마침내 맵 잠금이 해제되고 사용자 공간으로 다시 종료됩니다.

처음에는 다른 동시 스레드가 동시에 VM 맵의 상태를 수정할 수 있는 멀티 스레드 컨텍스트에서만 맵 잠금이 필요할 것이라고 생각했습니다. 그러나 단일 스레드를 사용하는 경우에도 take_vm_map_lock이 꺼져 있을 때 “커널 데이터 중단” 패닉이 발생하는 것을 보았는데, 이는 iOS(즉, macOS가 아닌)에서만 가끔씩 발생했습니다. 두 플랫폼 모두에서 지도 잠금을 사용할 때 안정적으로 작동하기 때문에 더 이상 조사하지 않았습니다.


## Appendix A: Considerations for Setup
smith_helper_init() 함수는 설정의 다음 부분을 담당합니다:

첫 번째 홀이 적어도 상수 target_hole_size만큼 커질 때까지 모든 홀을 할당합니다.
smith_run()의 1단계에서 5개의 VME를 할당할 수 있을 만큼 큰 마지막 홀을 찾습니다.
한 번에 하나씩 살펴봅시다.

파트 C에서 설명한 것처럼 PUAF 익스플로잇은 빨간색-검은색 트리와 구멍 목록의 상태를 손상시킵니다. 안타깝게도 그 결과 vm_map_enter() 및 vm_map_delete()와 같이 VM 맵에 영향을 미치는 대부분의 VM 작업은 여러 커널 패닉 중 하나를 트리거할 수 있습니다:

- 주소에 잠재적인 구멍이 아닌 기존 항목 [...]을 발견했습니다: [...]
- vmsel: 삽입 실패: [...]
- 삭제할 항목이 없습니다.
- 구멍 힌트가 실패했습니다: 구멍 항목 시작: [...]
- 구멍 힌트가 실패했습니다: 구멍 입력이 끝났습니다: [...]
- 잘못된 동작: H1: [...]

저를 믿으세요, 저는 모두 트리거했습니다. 그러나 첫 번째 구멍이 특정 크기보다 큰지 확인하면 최소한 해당 크기까지 VM_FLAGS_ANYWHERE 플래그를 사용하여 vm_allocate() 호출을 일부 수용할 수 있습니다. 또한 첫 번째 홀의 시작 주소가 충분히 높아서 새 VME를 삽입하는 동안 실수로 vme2b를 찾지 않도록 해야 하며, 그렇지 않으면 “기존 항목 발견” 패닉 또는 “VMSEL: INSERT FAILED” 패닉이 트리거될 수 있다는 점에 유의하세요.

마지막으로, 부록 B에서 설명하겠지만, smith_run()의 1단계에서 빨간색-검정색 트리의 오른쪽 하단에 가능한 한 많이 vme0에서 vme4까지 할당하고 싶습니다. 따라서 smith_helper_init()은 5개의 VME를 수용할 수 있을 만큼 큰 마지막 구멍을 찾습니다. VM 맵의 “하이엔드”는 일반적으로 비어 있으므로 이 5개의 VME는 거의 항상 [map->max_offset - (3X+5)P, map->max_offset)의 VA 범위로 들어가게 되며 여기서 (3X+5)P는 vme0~vme4의 총 크기입니다.


## Appendix B: Hacky Proof of Determinism

여기서는 공격자가 중요 구간 동안 대상 프로세스에서 실행되는 코드를 완전히 제어할 수 있다는 의미로 정의한 “제어된 컨텍스트”에서 익스플로잇이 결정론적으로 이루어질 수 있음을 보여드리려고 합니다. 예를 들어, 표적이 웹 콘텐츠인 경우 공격자는 취약점이 트리거되기 전에 다른 모든 스레드를 일시 중단했다가 정리 절차가 완료된 후 다시 시작할 수 있습니다. 또한, 공격자는 중요 구간에서 실행되는 코드를 신중하게 제작하여 PUAF 익스플로잇에 직접적으로 관련된 작업을 제외한 모든 VM 관련 작업을 피할 수 있다고 가정합니다. 특히, KRKW를 달성하는 익스플로잇의 일부를 포함하여 중요 구간 동안 액세스해야 하는 모든 메모리 영역은 미리 할당되고 결함이 발생해야 합니다. 이러한 엄격한 조건에서 임계 구간 동안 발생해야 하는 유일한 VM 관련 작업은 아래 상세 설명에 나와 있는 작업입니다. 기본적으로 결정론의 증명은 mach_vm_region() 및 유사한 API를 사용하더라도 사용자 공간에서 레드-블랙 트리의 정확한 레이아웃을 알 수 없음에도 불구하고 예측 가능한 방식으로 작동하는 VME 룩업에 달려 있습니다. 다행히도 중요한 구간에서 조회해야 하는 주소는 5개에 불과합니다:

주소 0에 대한 vm_map_lookup_entry()는 vme2a와 함께 TRUE를 반환해야 합니다.
주소 A에 대한 vm_map_lookup_entry()는 vme0과 함께 TRUE를 반환해야 합니다.
주소 B에 대한 vm_map_lookup_entry()는 vme1과 함께 TRUE를 반환해야 합니다.
주소 D에 대한 vm_map_lookup_entry()는 vme3과 함께 TRUE를 반환해야 합니다.
주소 E에 대한 vm_map_lookup_entry()는 vme4와 함께 TRUE를 반환해야 합니다.

불확실성은 vme2a와 vme2b가 [0:D)의 VA 범위를 포함한다는 사실에서 비롯됩니다. 따라서 vme0 및 vme1과 겹치므로 반드시 조회해야 합니다. 그러나 위의 조회는 한 가지 중요한 '공리'가 성립하는 한 예상대로 작동합니다. 즉, 어떤 경우에도 vme2a와 vme2b는 항상 빨간색-검정색 트리의 왼쪽에 있어야 하고, vme0에서 vme4는 항상 트리의 오른쪽에 있어야 한다는 것입니다. 이 '공리'는 지나치게 보수적이지만 증명을 단순화하는 데 도움이 된다는 점에 유의하세요. vme2a와 vme2b는 결정론적으로 가장 작은 2개의 시작 주소(즉, 각각 0과 1P)를 가지므로 항상 트리의 왼쪽 하단에 삽입됩니다. 재밸런싱이 발생하더라도 트리에 VME가 몇 개 이상 있는 한 트리의 루트나 오른쪽에 위치하는 것은 불가능합니다(기본적으로 트리에 VME가 몇 개 이상 있는 한). 그렇다면 VME0에서 VME4까지는 어떨까요? 당연히 가능한 한 오른쪽 하단에 많이 할당하여 재조정 시 루트나 왼쪽으로 재배치하는 것이 불가능하도록 해야 합니다. 다행히도 사용자 프로세스를 위한 가상 주소 공간의 “하이엔드”는 “로우엔드”보다 훨씬 더 드물기 때문에 이 요구 사항을 충족하는 것이 매우 쉽습니다. “공리"가 사실이라면, 주소 A에서 E까지의 모든 조회는 즉시 루트에서 바로 이동하여 vme2a와 vme2b를 완전히 피할 수 있습니다.덜 보수적인 조건은 빨간색-검정색 트리에서 vme2a와 vme2b가 결코 vme0에서 vme4보다 높지 않다는 것입니다.

그러나 회의적인 독자는 여전히 이 '공리'가 주소 A~E에 대한 조회의 올바른 동작을 보장하기에 충분하다고 확신하지 못할 수 있습니다. 왜냐하면 2단계에서 vme2는 VA 범위가 [C:0)이 되도록 클리핑될 것이기 때문입니다. 또한 vme0에서 vme4의 경우 인접하기 때문에 빨강-검정 트리에서 정확한 레이아웃을 가정해서는 안 됩니다. 그럼에도 불구하고 vm_map_lookup_entry()를 면밀히 분석해 보면 손상된 vme2가 다른 4개의 VME 위에 위치하더라도 문제가 되지 않는다는 것을 알 수 있습니다. 다행히도 오른쪽 하위 트리에 있는 VME의 전체 순서는 손상된 후에도 변경되지 않으므로 C보다 작은 주소에 대한 모든 조회는 여전히 vme2의 왼쪽으로, D보다 크거나 같은 주소에 대한 모든 조회는 여전히 vme2의 오른쪽으로 보장되므로 원래 VA 범위인 [C:D)가 그대로 유지되는 것처럼 보장됩니다. 실제로 영향을 받는 유일한 조회는 [C:D) VA 범위의 주소에 대한 것으로, 일반적으로 vme2를 사용하면 TRUE를 반환해야 하지만 손상된 끝 주소로 인해 FALSE를 반환합니다. 즉, PUAF 익스플로잇은 취약점이 트리거되기 직전인 2단계의 첫 번째 조회가 유일하게 발생하기 때문에 중요한 구간에서 이러한 조회를 피하도록 제작되었습니다.

더 이상 고민하지 않고, 여기 VM 맵과의 상호 작용에 관한 PUAF 악용에 대한 자세한 설명이 있습니다. 모든 라인 번호는 xnu-8792.81.2의 vm_map.c에서 가져온 것입니다.


