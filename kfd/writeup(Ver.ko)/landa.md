#  Landa

## Introduction
이 글에서는 XNU 커널의 취약점을 악용하는 방법을 소개합니다.

- CVE-2023-41974 가 할당됨 .
- iOS 17.0 및 macOS 14.0에서 수정되었습니다.
- 앱 샌드박스에서는 접근이 가능하지만 웹 콘텐츠 샌드박스에서는 접근이 불가능합니다.
- 란다는 읽기 전용 매핑에 쓰기를 허용하는 경쟁 조건이었던 P0 이슈 2361과 매우 유사하다는 점에 유의하세요. 구체적으로, vm_map_copy_overwrite_nested()는 대상 범위의 VME를 덮어쓸 수 있는지 확인하지만, vm_map_copy_overwrite_unaligned()는 맵 잠금을 해제하고 다시 가져온 후 동일한 검사를 수행하지 않을 수 있습니다. Landa는 동일한 방식으로 작동하지만 대신 '전환 중'인 VME에 대해 작동합니다.

이 익스플로잇은 다음에서 성공적으로 테스트되었습니다.

iOS 16.5 및 16.5.1(iPhone 14 Pro Max)
macOS 13.4 및 13.4.1(MacBook Air M2 2022)
아래에 표시된 모든 코드 조각은 xnu-8796.101.5 에서 가져온 것입니다 .

## Part A: From Vulnerability to PUAF
익스플로잇의 이 부분은 landa.h에 있는 landa_run() 함수에 레이블이 지정된 3단계로 구성되어 있습니다. 각 단계는 아래에서 자세히 설명하며, 익스플로잇의 특정 지점에서 관련 커널 상태를 보여주는 그림과 함께 설명합니다. 녹색 상자는 VME, 노란색 상자는 VMO, 보라색 상자는 VMC를 나타내며 빨간색 텍스트는 이전 그림과 비교하여 차이점을 강조합니다. 또한 X는 원하는 PUAF 페이지 수를 나타내고 P는 페이지 크기(즉, 16384바이트)를 나타냅니다. 마지막으로, 각 단계에 대한 설명을 읽기 전에 여기서는 반복하지 않으므로 landa_run() 함수에서 해당 코드를 확인하시기 바랍니다.

### STEP 1:
이 단계는 2단계의 경쟁 조건에서 간단히 이길 수 있도록 설정을 담당합니다. 하위 단계 1A에서는 2단계에서 복사본의 소스 범위로 사용될 임의의 주소 A에 (X+2) 페이지의 메모리 영역을 vm_allocate()합니다. 그런 다음 해당 메모리 영역을 아래 목록에 오름차순으로 설명된 세 개의 개별 VME로 분할합니다:

- src_vme_1의 크기는 1페이지이며, src_vm_1에 대한 유일한 참조를 소유하고 있습니다.
- src_vme_2의 크기는 1페이지이며, src_vmo_2에 대한 유일한 참조를 소유합니다.
- src_vme_3의 크기는 X 페이지이며 src_vmo_3에 대한 유일한 참조를 소유합니다.

모든 소스 VME는 VM_FLAGS_PURGABLE 플래그를 사용하여 복사_전략이 MEMORY_OBJECT_COPY_NONE인 퍼지 가능 오브젝트로 초기화됩니다. 또한 전체 소스 범위는 memset()으로 결함이 있습니다. 다음은 하위 단계 1A 이후의 관련 커널 상태의 그림입니다:

![landa-figure1.png](figures/landa-figure1.png)

하위 단계 1B에서는 2단계에서 마지막 페이지를 제외한 복사본의 대상 범위로 사용될 임의의 주소 B에 (X+3)페이지의 메모리 영역을 vm_allocate()합니다. 그런 다음 해당 메모리 영역을 아래 목록에 오름차순으로 설명된 네 개의 개별 VME로 분할합니다:

- dst_vme_1의 크기는 1페이지이며 dst_vm_o_1에 대한 유일한 참조를 소유합니다. 또한 dst_vme_1->user_wired_count는 간단한 mlock() for-loop를 사용하여 MAX_WIRE_COUNT로 설정됩니다.
- dst_vme_2의 크기는 1페이지이며 dst_vm_o_2에 대한 유일한 참조를 소유하고 있습니다. 또한 vm_remap()으로 자체적으로 리매핑하여 dst_vme_2->is_shared를 TRUE로 설정하고, mlock() 한 번 호출로 dst_vme_2->user_wired_count를 1로 설정할 수 있습니다.

원래는 마지막 (X+1) 페이지에 단일 VME가 할당되지만, 마지막 페이지를 vm_protect()로 읽기 전용으로 표시하여 두 개의 VME로 클립됩니다:

- dst_vme_3의 크기는 X 페이지이며 dst_vm_o_3에 대한 두 개의 참조 중 하나를 소유합니다.
- dst_vme_4는 크기가 1페이지이고 dst_vmo_3의 다른 참조를 소유합니다. 또한 dst_vme_4->protection은 vm_-protect()에 의해 VM_PROT_READ로 설정됩니다.

다시 한 번, 모든 대상 VME는 VM_FLAGS_PURGABLE 플래그를 사용하여 복사 전략이 MEMORY_OBJECT_COPY_NONE인 퍼지 가능한 오브젝트로 초기화된다는 점에 유의하십시오. 또한 dst_vme_4의 읽기 전용 페이지를 제외한 전체 대상 범위가 memset()으로 오류를 일으킵니다. 다음은 하위 단계 1B 이후의 관련 커널 상태를 보여주는 그림입니다:

![landa-figure2.png](figures/landa-figure2.png)

### STEP 2:
본격적으로 경쟁 조건을 트리거하기 전에 먼저 다른 스레드를 생성하여 landa_helper_spinner_pthread() 함수를 실행하여 주소 B(즉, dst_vme_1에서 dst_vme_3)에서 시작하는 (X+2) 페이지를 바쁜 루프로 배선하려고 시도합니다. 그러나 dst_vme_1->user_wired_count가 이미 MAX_WIRE_COUNT로 설정되어 있으므로 mlock()은 기본적으로 아무 작업도 하지 않고 ENOMEM만 반환합니다. 다음으로 메인 스레드에서 vm_copy()를 호출하여 주소 A에서 주소 B로 (X+2) 페이지를 복사하여 경쟁 조건을 악용합니다.

하위 단계 2A에서는 vm_copy()의 vm_map_copyin() 부분을 고려합니다. 소스 범위는 전적으로 퍼지 가능한 메모리로 구성되어 있으므로 쓰기 시 복사 최적화가 적용되지 않습니다. 대신, 3개의 소스 VMO인 src_vmo_1에서 src_vmo_3까지 각각 복사된 페이지(X+2)를 보유하기 위해 3개의 새로운 VMO인 copy_vmo_1부터 copy_vmo_3까지가 할당됩니다. 이 작업은 vm_map_copyin_internal()에서 vm_object_copy_strategically()를 세 번 호출하는 동안 이루어집니다. 마지막으로, vm_map_copyin()이 반환되면 출력 VMC에는 복사_vme_1에서 복사_vme_3까지 3개의 임시 VME가 포함되며, 각 임시 VME는 해당 시점에 복사_vmo_1에서 복사_vmo_3에 대한 유일한 참조를 각각 소유하고 있습니다. 다음은 하위 단계 2A 이후의 관련 커널 상태를 보여주는 그림입니다:

![landa-figure3.png](figures/landa-figure3.png)

하위 단계 2B에서는 스피너 스레드에서 mlock()이 더 이상 ENOMEM에 멈추지 않는 지점까지 vm_copy()의 vm_map_copy_overwrite() 부분을 고려합니다. 첫째, 복사본은 완전히 페이지 정렬되므로 vm_map_copy_overwrite()는 VMC를 “헤드” 또는 “테일”로 분할하지 않으며, vm_map_copy_overwrite_nested()를 한 번만 호출합니다. P0 이슈 2361과 마찬가지로 이 함수는 모든 대상 VME를 덮어쓸 수 있는지 확인하며, 여기에는 VME가 “전환 중”으로 표시되지 않았는지 확인하는 것도 포함됩니다. 이 시점에서 mlock()은 여전히 dst_vme_1->user_wired_count가 MAX_WIRE_COUNT와 같기 때문에 대상 범위(즉, dst_vme_1에서 dst_vme_3)가 전환 중이 아닌 것이 보장됩니다. 따라서 vm_map_copy_overwrite_nested()가 진행되며 맵 잠금을 유지한 상태에서 vm_map_copy_overwrite_aligned()를 호출합니다. vm_map_copy_overwrite_aligned()에서 최상위 수준의 동안 루프가 세 번 반복됩니다:

첫 번째 반복에서는 copy_entry == copy_vme_1, entry == dst_vme_1, object == dst_vmo_1이 됩니다.
두 번째 반복에서는 copy_entry == copy_vme_2, entry == dst_vme_2, object == dst_vmo_2가 됩니다.
세 번째 반복에서는 COPY_ENTRY == COPY_VME_3, ENTRY == DST_VME_3, OBJECT == DST_VMO_3이 됩니다.
또한 복사 항목과 항목의 각 쌍이 동일한 크기를 갖도록 만들어져 클리핑이 발생하지 않는다는 점에 유의하세요. 마지막으로 아래 스니펫에 표시된 것처럼 '빠른 경로'를 사용할지 '느린 경로'를 사용할지 결정하는 if-else 문에 도달합니다:

```c
// Location: osfmk/vm/vm_map.c

static kern_return_t
vm_map_copy_overwrite_aligned(
    vm_map_t        dst_map,
    vm_map_entry_t  tmp_entry,
    vm_map_copy_t   copy,
    vm_map_offset_t start,
    __unused pmap_t pmap)
{
    vm_object_t     object;
    vm_map_entry_t  copy_entry;
    vm_map_size_t   copy_size;
    vm_map_size_t   size;
    vm_map_entry_t  entry;

    while ((copy_entry = vm_map_copy_first_entry(copy)) != vm_map_copy_to_entry(copy)) {
        ...

        // this if-else statement decides whether we take the fast path or the slow path
        if (((!entry->is_shared) &&
             ((object == VM_OBJECT_NULL) || (object->internal && !object->true_share))) ||
            (entry->needs_copy)) {
            // fast path branch
            ...
        } else {
            // slow path branch
            ...
        }
    }

    return KERN_SUCCESS;
}
```

첫 번째 반복 중에 dst_vme_1과 dst_vm_o_1은 빠른 경로를 사용하기 위한 모든 조건을 충족합니다. 아래 코드 조각은 첫 번째 반복 중에 빠른 경로 분기 내부에서 일어나는 일을 보여줍니다:

```c
{
    // NOTE: this is inside the fast path branch
    vm_object_t         old_object = VME_OBJECT(entry); // old_object := dst_vmo_1
    vm_object_offset_t  old_offset = VME_OFFSET(entry); // old_offset := 0
    vm_object_offset_t  offset;

    if ((old_object == VME_OBJECT(copy_entry)) &&
        (old_offset == VME_OFFSET(copy_entry))) { // branch not taken because of different objects
        ...
    }

    ...

    if ((dst_map->pmap != kernel_pmap) &&
        (VME_ALIAS(entry) >= VM_MEMORY_MALLOC) &&
        (VME_ALIAS(entry) <= VM_MEMORY_MALLOC_MEDIUM)) { // branch not taken because alias is 0
        ...
    }

    if (old_object != VM_OBJECT_NULL) { // branch taken
        if (entry->is_sub_map) { // branch not taken because dst_vme_1->is_sub_map == FALSE
            ...
        } else {
            if (dst_map->mapped_in_other_pmaps) { // branch not taken
                ...
            } else {
                // PTEs in the VA range of dst_vme_1 are removed here
                pmap_remove_options(
                    dst_map->pmap,
                    (addr64_t)(entry->vme_start),
                    (addr64_t)(entry->vme_end),
                    PMAP_OPTIONS_REMOVE);
            }
            // dst_vmo_1 is deallocated and reaped here
            vm_object_deallocate(old_object);
        }
    }

    ...

    VME_OBJECT_SET(entry, VME_OBJECT(copy_entry), false, 0); // VME_OBJECT(dst_vme_1) := copy_vmo_1
    object = VME_OBJECT(entry);                              // object := copy_vmo_1
    entry->needs_copy = copy_entry->needs_copy;              // dst_vme_1->needs_copy := FALSE
    entry->wired_count = 0;                                  // dst_vme_1->wired_count := 0
    entry->user_wired_count = 0;                             // dst_vme_1->user_wired_count := 0
    offset = VME_OFFSET(copy_entry);                         // offset := 0
    VME_OFFSET_SET(entry, offset);                           // VME_OFFSET(dst_vme_1) := 0

    // copy_vme_1 is unlinked and deallocated here
    vm_map_copy_entry_unlink(copy, copy_entry);
    vm_map_copy_entry_dispose(copy_entry);

    start = tmp_entry->vme_end; // start := B+1P
    tmp_entry = tmp_entry->vme_next; // tmp_entry := dst_vme_2
}
```

첫 번째 반복 중에 dst_vme_1과 dst_vm_o_1은 빠른 경로를 사용하기 위한 모든 조건을 충족합니다. 아래 코드 조각은 첫 번째 반복 중에 빠른 경로 분기 내부에서 일어나는 일을 보여줍니다:

```c
{
    // NOTE: this is inside the slow path branch
    vm_map_version_t    version;
    vm_object_t         dst_object;
    vm_object_offset_t  dst_offset;
    kern_return_t       r;

slow_copy:
    if (entry->needs_copy) { // branch not taken because dst_vme_2->needs_copy == FALSE
        ...
    }

    dst_object = VME_OBJECT(entry); // dst_object := dst_vmo_2
    dst_offset = VME_OFFSET(entry); // dst_offset := 0

    if (dst_object == VM_OBJECT_NULL) { // branch not taken
        ...
    }

    vm_object_reference(dst_object); // dst_vmo_2->ref_count++
    version.main_timestamp = dst_map->timestamp + 1;
    vm_map_unlock(dst_map); // map lock is dropped here

    copy_size = size; // copy_size := 1P

    r = vm_fault_copy(
        VME_OBJECT(copy_entry),
        VME_OFFSET(copy_entry),
        &copy_size,
        dst_object,
        dst_offset,
        dst_map,
        &version,
        THREAD_UNINT);

    vm_object_deallocate(dst_object); // dst_vmo_2->ref_count--

    if (r != KERN_SUCCESS) { // branch not taken because vm_fault_copy() returns KERN_SUCCESS
        ...
    }

    if (copy_size != 0) { // branch taken because copy_size == 1P
        vm_map_copy_clip_end(copy, copy_entry, copy_entry->vme_start + copy_size);
        vm_map_copy_entry_unlink(copy, copy_entry);
        vm_object_deallocate(VME_OBJECT(copy_entry)); // copy_vmo_2 is deallocated here
        vm_map_copy_entry_dispose(copy_entry); // copy_vme_2 is deallocated here
    }

    start += copy_size; // start := B+2P
    vm_map_lock(dst_map); // map lock taken back here

    // NOTE: the spinner thread should always take the map lock before we take it back,
    // but the possible outcomes of the race condition will be discussed later
    if (version.main_timestamp == dst_map->timestamp && copy_size != 0) { // branch not taken
        ...
    } else {
        if (!vm_map_lookup_entry(dst_map, start, &tmp_entry)) { // tmp_entry := dst_vme_3
            ...
        }
        ...
    }
}
```

간단히 말해, dst_vmo_2에서 임시 참조를 취한 다음 vm_fault_copy()를 호출하기 전에 맵 잠금을 해제하여 copy_vmo_2에서 dst_vmo_2로 페이지의 물리적 복사를 수행합니다. 맵 잠금이 해제된 후 어떤 일이 발생하는지 알아보기 전에 하위 단계 2B 이후의 관련 커널 상태를 그림으로 보여드리겠습니다:

![landa-figure4.png](figures/landa-figure4.png)

위 코드 조각의 주석에서 언급했듯이, 스피너 스레드는 항상 맵 잠금을 가져온 다음 vm_fault_copy()가 반환될 때 vm_map_copy_overwrite_aligned()가 이를 되찾아야 합니다. 따라서 이제 스피너 스레드로 관심을 옮겨 보겠습니다. 여기서 mlock()은 vm_map_wire_kernel()을 호출하고, 이 함수는 다시 vm_map_wire_nested()를 호출합니다. 이 함수는 맵 잠금을 가져와 주소 B를 조회하여 dst_vme_1을 반환합니다. 그런 다음 vm_map_wire_nested()에서 최상위 수준의 동안 루프가 dst_vme_1, dst_vme_2 및 dst_vme_3에 대해 각각 하나씩 세 번 반복됩니다.


첫 번째 반복 중에 항목은 copy_vm_o_1에 대한 참조가 있는 dst_vme_1로 설정됩니다. copy_vmo_1의 복사 전략이 MEMORY_OBJECT_COPY_SYMMETRIC이므로 vm_map_wire_nested()는 dst_vme_1에서 VME_OBJECT_SHADOW()를 호출하지만 섀도 생성은 건너뜁니다. 그러나 copy_vmo_1->copy_strategy는 MEMORY_OBJECT_COPY_DELAY로 설정되고 copy_vmo_1->true_share는 TRUE로 설정됩니다. 이 중 어느 것도 익스플로잇과 실제로 관련이 없으며, XNU 소스 코드를 따라하는 경우를 대비하여 언급하는 것뿐입니다. 다음으로, vm_map_wire_nested()는 add_wire_counts()를 호출합니다. 이번에는 dst_vme_1->wired_count와 dst_vme_1->user_wired_count가 0으로 재설정되었으므로 add_wire_counts()는 KERN_FAILURE를 반환하는 대신 각각을 1로 봅핑합니다. 그런 다음 dst_vme_1->in_transition이 TRUE로 설정되고 맵이 잠금 해제되며 vm_fault_wire()가 호출되어 copy_vmo_1의 단일 페이지에 와이어가 연결됩니다. 다시 한 번, vm_map_wire_nested()가 맵 잠금을 다시 가져와야 vm_fault_copy()가 반환될 때 vm_map_copy_overwrite_aligned()가 이를 되찾을 수 있습니다. 그러나 단일 페이지를 배선하는 것이 물리적으로 페이지를 복사하는 것보다 훨씬 빠르기 때문에 이 경쟁에서 이기기 쉽습니다. 한 가지 중요한 점은 경쟁에서 지더라도 타임스탬프 검사 실패 후 조회가 여전히 dst_vme_1을 반환하도록 보장되므로 “vm_map_wire: 재조회 실패” 패닉이 트리거되지 않도록 보장된다는 것입니다. 대신 익스플로잇을 다시 시작하면 됩니다.  하지만 실제로는 우리가 항상 이 경주에서 이기므로 계속 진행하겠습니다. 맵 잠금이 다시 취해지면 dst_vme_1->in_transition이 FALSE로 다시 설정되고 다음 VME로 이동합니다.

두 번째 반복 중에 항목은 dst_vm_o_2에 대한 참조가 있는 dst_vme_2로 설정됩니다. 그러나 dst_vme_2->wired_count는 이미 1로 설정되어 있으므로 add_wire_counts()는 단순히 dst_vme_2->user_wired_count를 2로 상향 조정하고 맵 잠금을 해제하지 않고 즉시 다음 VME로 이동합니다.

세 번째 반복 중에 항목은 dst_vmo_3에 대한 참조가 있는 dst_vme_3으로 설정됩니다. 첫 번째 반복과 달리 dst_vmo_3의 복사 전략은 MEMORY_OBJECT_COPY_NONE이므로 섀도 생성이 시도되지 않습니다. 다음으로 vm_map_wire_nested()는 add_wire_counts()를 호출하여 dst_vme_3->wired_count와 dst_vme_3->user_wired_count를 모두 1로 늘립니다. 그런 다음 dst_vme_3->in_transition이 TRUE로 설정되고 맵이 잠금 해제되며 vm_fault_wire()를 호출하여 dst_vmo_3의 X 페이지를 배선합니다. 결정적으로, vm_fault_wire()는 dst_vme_3의 얕은 비트 단위 복사본을 수신하므로 나중에 맵이 잠금 해제된 상태에서 VME_OBJECT(dst_vme_3)가 수정되더라도 항상 dst_vmo_3을 가리키게 됩니다. 기술적으로 dst_vme_3은 “전환 중”으로 표시되어 있으므로 절대 이런 일이 발생해서는 안 되지만, 바로 이것이 우리의 경쟁 조건이 악용하는 부분입니다. 이 시점에서 vm_fault_wire()는 dst_vmo_3의 각 X 페이지에 대해 vm_fault_wire_fast()를 호출합니다. 그러나 이번에는 vm_fault_wire()가 dst_vmo_3의 모든 X 페이지 배선을 완료하기 전에 vm_fault_copy()가 dst_vmo_2의 단일 페이지 복사를 물리적으로 완료하여 vm_map_copy_overwrite_aligned()가 여기서 맵 잠금을 되찾을 것으로 예상합니다. 이 레이스의 가능한 결과에 대해서는 2단계 마지막에 설명할 예정이지만, 먼저 이런 상황이 발생한다고 가정해 보겠습니다. 계속 진행하기 전에 2C 하위 단계 이후의 관련 커널 상태를 그림으로 보여드리겠습니다:

![landa-figure5.png](figures/landa-figure5.png)

메인 스레드로 돌아가면 위의 코드 조각에서 볼 수 있듯이 vm_fault_copy()가 반환된 후 느린 경로에 대해 dst_vmo_2의 추가 참조가 해제된 다음 copy_vme_2와 copy_vmo_2가 할당 해제되고 마지막으로 맵 잠금이 다시 취해집니다. 맵 타임스탬프가 변경되었으므로 조회가 수행되어 dst_vme_3이 반환되고, vm_map_copy_overwrite_aligned()의 세 번째이자 마지막 반복인 동안 루프로 이동합니다. 이번에는 dst_vme_3과 dst_vm_o_3이 빠른 경로를 취하기 위한 모든 조건을 충족합니다. 아래 코드 조각은 세 번째 반복 중에 빠른 경로 분기 내부에서 어떤 일이 일어나는지 보여줍니다:

```
{
    // NOTE: this is inside the fast path branch
    vm_object_t         old_object = VME_OBJECT(entry); // old_object := dst_vmo_3
    vm_object_offset_t  old_offset = VME_OFFSET(entry); // old_offset := 0
    vm_object_offset_t  offset;

    if ((old_object == VME_OBJECT(copy_entry)) &&
        (old_offset == VME_OFFSET(copy_entry))) { // branch not taken because of different objects
        ...
    }

    ...

    if ((dst_map->pmap != kernel_pmap) &&
        (VME_ALIAS(entry) >= VM_MEMORY_MALLOC) &&
        (VME_ALIAS(entry) <= VM_MEMORY_MALLOC_MEDIUM)) { // branch not taken because alias is 0
        ...
    }

    if (old_object != VM_OBJECT_NULL) { // branch taken
        if (entry->is_sub_map) { // branch not taken because dst_vme_3->is_sub_map == FALSE
            ...
        } else {
            if (dst_map->mapped_in_other_pmaps) { // branch not taken
                ...
            } else {
                // PTEs in the VA range of dst_vme_3 are removed here
                pmap_remove_options(
                    dst_map->pmap,
                    (addr64_t)(entry->vme_start),
                    (addr64_t)(entry->vme_end),
                    PMAP_OPTIONS_REMOVE);
            }
            // dst_vmo_3->ref_count drops to 1
            vm_object_deallocate(old_object);
        }
    }

    ...

    VME_OBJECT_SET(entry, VME_OBJECT(copy_entry), false, 0); // VME_OBJECT(dst_vme_3) := copy_vmo_3
    object = VME_OBJECT(entry);                              // object := copy_vmo_3
    entry->needs_copy = copy_entry->needs_copy;              // dst_vme_3->needs_copy := FALSE
    entry->wired_count = 0;                                  // dst_vme_3->wired_count := 0
    entry->user_wired_count = 0;                             // dst_vme_3->user_wired_count := 0
    offset = VME_OFFSET(copy_entry);                         // offset := 0
    VME_OFFSET_SET(entry, offset);                           // VME_OFFSET(dst_vme_3) := 0

    // copy_vme_3 is unlinked and deallocated here
    vm_map_copy_entry_unlink(copy, copy_entry);
    vm_map_copy_entry_dispose(copy_entry);

    start = tmp_entry->vme_end; // start := B+(X+2)P
    tmp_entry = tmp_entry->vme_next; // tmp_entry := dst_vme_4 but we exit the loop here
}
```

요컨대, dst_vme_3의 VA 범위에 있는 PTE가 제거되는데, 이는 PUAF 프리미티브를 얻으려는 PTE이기 때문에 관련이 있습니다. 다음으로, dst_vm_3->ref_count가 1로 떨어지고 VME_OBJECT(dst_vme_3)가 dst_vm_3 대신 copy_vm_3으로 업데이트됩니다. 그 후 VMC가 비어 있으므로 vm_map_copy_overwrite_aligned()가 수행되고 vm_copy()는 KERN_SUCCESS를 반환합니다.

한편, 스피너 스레드로 돌아가면 vm_fault_wire()는 계속해서 dst_vmo_3의 X 페이지를 와이어링하여 읽기 및 쓰기 권한이 모두 있는 해당 페이지의 물리적 주소로 dst_vme_3의 VA 범위 내 PTE에 다시 입력합니다. 그 후 vm_map_wire_nested()가 완료되고 mlock()이 0을 반환합니다. 다음은 2단계의 마지막 하위 단계인 하위 단계 2D 이후의 관련 커널 상태를 보여주는 그림입니다:

![landa-figure6.png](figures/landa-figure6.png)

약속한 대로 이제 다양한 경합 조건의 가능한 결과에 대해 설명하겠습니다. 두 번째 반복 중에 vm_map_copy_overwrite_aligned()가 vm_fault_copy()를 호출하기 전에 맵 잠금을 해제하는 시점까지는 익스플로잇이 완전히 결정론적이라는 점에 유의하시기 바랍니다. 이제 세 가지 시나리오를 고려해 보겠습니다:

1. vm_map_copy_overwrite_aligned()가 vm_map_wire_nested()가 스피너 스레드에서 처음으로 맵 잠금을 가져올 기회를 갖기도 전에 다시 가져오는 경우인데, 이는 매우 드문 경우입니다. 이 경우 vm_map_copy_overwrite_aligned()는 맵 잠금과 함께 완료될 때까지 실행됩니다. 따라서 맵 잠금이 두 번째로 해제되기 전에 dst_vme_3에서 dst_vm_o_3으로의 참조가 copy_vm_o_3으로 대체됩니다. 따라서 결국 vm_fault_wire()가 수신하는 dst_vme_3의 얕은 비트 단위 복사본도 copy_vmo_3을 가리키게 됩니다. 결과적으로 dst_vmo_3의 페이지 대신 copy_vmo_3의 페이지가 유선 연결됩니다. PUAF 익스플로잇은 실패하지만 안전하게 실패하며 필요한 만큼 재시도할 수 있습니다.
2. vm_map_wire_nested()는 맵 잠금을 가져와서 dst_vme_1을 전환 중으로 표시한 다음 vm_fault_wire()를 호출하기 전에 맵 잠금을 해제합니다. 그러나 vm_map_copy_overwrite_aligned()는 vm_map_wire_nested()가 동일한 작업을 수행하기 전에 이를 다시 가져옵니다. 이는 첫 번째 시나리오보다는 가능성이 높지만, vm_fault_copy()에서 물리적으로 1페이지를 복사하는 것이 vm_fault_wire_fast()에서 1PTE를 배선하는 것보다 훨씬 느리기 때문에 여전히 가능성은 낮습니다. 그럼에도 불구하고 이런 일이 발생한다면 결과는 같은 이유로 첫 번째 시나리오와 동일할 것입니다. vm_map_wire_nested()가 얕은 비트 단위로 복사할 때 dst_vme_3의 참조가 이미 copy_vmo_3으로 대체될 것입니다.
3. 반대로, vm_map_wire_nested()는 vm_map_copy_overwrite_aligned()가 맵 잠금을 되찾기 전에 완료까지 실행할 수 있습니다. 즉, vm_fault_copy()에서 단일 페이지의 물리적 복사본이 완료되기 전에 vm_fault_wire_fast()가 (X+1) 번 실행됩니다. X 값이 큰 경우에는 vm_fault_wire_fast()를 호출할 때마다 오브젝트 잠금과 페이지 큐 잠금 등을 모두 수행해야 하므로 이 역시 가능성은 낮습니다. 그럼에도 불구하고 이런 일이 발생한다면 dst_vm_o_3의 VA 범위에서 dst_vme_3의 X 페이지를 성공적으로 와이어링했을 것이지만, 나중에 vm_map_copy_overwrite_aligned()가 맵 잠금을 다시 가져와 dst_vm_o_3에 대한 참조를 copy_vm_o_3으로 바꿀 때 모든 PTE가 제거될 것입니다. 다시 한 번, PUAF 익스플로잇은 안전하게 실패하고 필요에 따라 재시도할 수 있습니다.

물론 또 다른 가능한 시나리오가 있습니다. 어느 시점에서 메인 스레드는 vm_fault_copy()를 실행하느라 바쁘고 스피너 스레드는 vm_fault_wire()를 실행하느라 바쁘고 둘 다 맵 잠금을 보유하지 않는 경우입니다. 이 경우 vm_fault_wire()가 dst_vme_3의 VA 범위 시작 부분에 특정 수의 PTE를 배선한 다음 vm_fault_copy()가 반환하고 vm_map_copy_overwrite_aligned()가 dst_vme_3에 대해 pmap_remove_options()를 호출하면 모든 PTE를 제거할 수 있습니다. 즉, 그 후에는 vm_fault_wire()가 dst_vm_o_3의 나머지 페이지를 계속 배선할 수 있으며, 그러면 해당 VA 범위의 나머지 PTE가 다시 입력됩니다. 결국, X 페이지의 일부에 PUAF 프리미티브가 남게 됩니다. 그리고 이런 일이 가끔 발생합니다! X를 2048로 설정했을 때 테스트한 결과, 익스플로잇은 대부분의 경우 2048페이지 모두에서 PUAF 프리미티브를 획득합니다. 그러나 때때로 테스트 결과 dst_vme_3 범위의 첫 번째 PTE가 클리어되어 익스플로잇이 2047 페이지에서 PUAF 프리미티브를 획득하는 것으로 나타났습니다. 이것이 현재 익스플로잇의 상태에서 제가 관찰한 유일한 두 가지 결과입니다. 과거에는 몇 가지를 조정하기 전에는 최대 4개의 PTE가 클리어되는 것을 본 적이 있습니다. 어쨌든, 이 PUAF 익스플로잇은 안전하기 때문에 처음에 PUAF 프리미티브에서 KRKW 프리미티브를 얻지 못하면 반복할 수 있습니다.

## Part B: From PUAF to KRKW

## Part C: From KRKW to Cleanup

