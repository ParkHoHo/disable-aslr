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


## Part B: From PUAF to KRKW

## Part C: From KRKW to Cleanup

## Appendix A: Considerations for Setup

## Appendix B: Hacky Proof of Determinism


