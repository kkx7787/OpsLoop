# OpsLoop 인프라 코드

콘솔에서 손으로 만든 자원을 코드의 관리 아래로 옮긴다.

## 왜 새로 만들지 않는가

수집 노드에는 축적된 원문 로그가 있고, 공인 주소가 바뀌면 유입 중인
공격이 끊긴다. 재현성을 확보하려고 실측 데이터를 버리는 것은 순서가
뒤바뀐 일이므로, 기존 자원을 가져오는 방식을 택했다.

## 준비

로컬에 AWS 자격증명이 필요하다. 저장소에는 어떤 키도 두지 않는다.

```bash
aws configure          # ~/.aws/credentials 에 저장된다
aws sts get-caller-identity
```

## 절차

### 1. 값 채우기

```bash
cp terraform.tfvars.example terraform.tfvars
```

콘솔에서 확인할 값은 넷이다.

| 값 | 확인 위치 |
|---|---|
| `vpc_id`, `subnet_id` | EC2 → 인스턴스 → 네트워킹 탭 |
| `import_*_instance_id` | 인스턴스 목록의 인스턴스 ID |
| `import_*_sg_id` | EC2 → 보안 그룹 |
| `admin_cidr` | 현재 공인 IP + `/32` |

AMI 두 개는 아직 비워둔다. 3단계에서 채운다.

### 2. 초기화와 첫 가져오기

```bash
terraform init
terraform plan
```

AMI 가 비어 있어 이 단계에서는 오류가 난다. 임시로 아무 값이나 넣고
가져오기를 먼저 수행한다.

```bash
terraform plan  -var 'honeypot_ami=ami-0' -var 'app_ami=ami-0'
terraform apply -var 'honeypot_ami=ami-0' -var 'app_ami=ami-0'
```

가져오기가 끝나면 상태 파일에 실제 값이 들어온다.

### 3. 실제 AMI 채우기

```bash
terraform state show aws_instance.honeypot | grep -m1 '^ *ami'
terraform state show aws_instance.app      | grep -m1 '^ *ami'
```

두 값을 `terraform.tfvars` 에 옮겨 적는다.

### 4. 계획이 비워질 때까지 반복

```bash
terraform plan
```

`No changes` 가 나올 때까지 코드를 실제 상태에 맞춘다. 콘솔에서 만든
자원에는 코드에 적지 않은 기본값이 붙어 있어 몇 차례 조정이 필요하다.

**계획에 `destroy` 나 `replace` 가 보이면 적용하지 않는다.** 인스턴스에
`prevent_destroy` 를 걸어두어 실수로 지워지지는 않으나, 계획이 그렇게
나온다는 것은 코드가 실제와 어긋났다는 뜻이다.

### 5. 마무리

계획이 비워지면 가져오기용 잔재를 제거한다.

```bash
rm imports.tf
```

`variables.tf` 의 `import_*` 변수와 `terraform.tfvars` 의 해당 항목도
함께 지운다. 이 시점부터 코드가 인프라의 정본이다.

## 이후

```bash
terraform plan     # 콘솔에서 누가 무엇을 바꿨는지 드러난다
```

계획에 차이가 잡히면 둘 중 하나다. 콘솔에서 직접 손댔거나, 코드를 고치고
아직 적용하지 않았거나. 어느 쪽이든 원인을 확인한 뒤 한쪽으로 맞춘다.

## 남은 과제

- 상태 파일을 S3 로 옮긴다. 백업용 버킷을 만들 때 함께 처리한다
- 노드 증설분(로드밸런서, 콘솔 백엔드 2대)을 코드에 추가한다
- cloud-init 으로 초기 설정을 코드화한다. 현재는 설치 스크립트가 그 역할을 한다
