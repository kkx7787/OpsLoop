# OpsLoop 로고 v1

2026-10-03 사용자가 첨부한 세 로고 중 가운데 안을 기준으로 한다. 기존 검은 favicon과 일반 순환 아이콘을 대체한다.

- `opsloop-wordmark-v1.png`: imagegen으로 가운데 안을 투명 배경으로 재구성한 워드마크. 로그인 화면에서 사용한다. 참조 이미지의 글자를 그대로 잘라낸 파일은 아니므로 원본과 픽셀 단위로 같지는 않다.
- `opsloop-mark-v1.svg`: 화살표만 남긴 32×32 벡터. favicon에 사용하며, 사이드바의 `IconLogo`도 같은 두 경로를 사용한다. 탭이 어두워도 식별하도록 favicon에는 흰 바탕을 둔다. 16·24·32·48·64px에서 확인했다.

운영 화면의 제목·본문·표는 기존 글꼴을 유지한다. 워드마크의 기울기와 그라데이션을 다른 요소로 넓히지 않는다. 두 제품 이미지의 정확한 `/brand/…` 경로만 로그인 전에 공개하고 다른 앱 파일의 인증은 유지한다. 파일을 교체할 때는 v2처럼 새 이름을 사용하고 로그인·favicon·사이드바를 함께 확인한다.

생성 프롬프트:

> Edit the attached reference sheet into ONE clean transparent logo asset: isolate and faithfully reproduce ONLY the CENTER OpsLoop logo. Keep the exact italic handwritten/script navy lettering 'OpsLoop', including the distinctive O and L forms and slant. Keep the two sweeping blue circular arrows, the top arrow sweeping down-left and the bottom arrow sweeping up-right; preserve their center-logo layout and tasteful cyan-to-blue gradient. Remove all other logo options and remove the white background. Do not invent a new logo, no extra marks, no tagline, no card, no shadow, no 3D. The output should be tightly composed but with safe transparent padding on all sides, high resolution, horizontal aspect ratio about 2.1:1. This is a production wordmark for a restrained IT operations monitoring application.

`transparent_background=true`로 생성했다. SVG는 생성 이미지를 자동 추적하지 않고 작은 크기의 식별성을 기준으로 직접 작성했다.
