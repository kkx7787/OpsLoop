import { useState, type ReactNode } from 'react'
import { ApiError } from '@/api/errors'
import { permission } from '@/auth/roles'
import {
  AsOfStatus,
  Badge,
  Banner,
  Button,
  Card,
  CardHeader,
  Chip,
  CtiBadge,
  EmptyState,
  ErrorState,
  ForbiddenState,
  FormField,
  Gated,
  IconDatabaseOff,
  InfoTip,
  Input,
  Kbd,
  LoadingState,
  NotFoundState,
  OpsSummary,
  PageHeader,
  SegmentedControl,
  Select,
  SessionExpiredState,
  SeverityBadge,
  StatCard,
  StatusDot,
  Switch,
  Textarea,
  Time,
  UntrustedText,
  VerdictBadge,
  type OpsView,
} from '@/components'
import { SEVERITIES, VERDICTS } from '@/lib/domain'

/**
 * 공통 컴포넌트 모음. 와이어프레임(States · Error · Main.dc.html)과 눈으로 맞춰 보는 자리다.
 * 개발 서버에서만 /dev/components 로 열린다(src/app/router.tsx). 운영 번들에는 들어가지 않는다.
 */

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card padding="none">
      <CardHeader title={title} />
      <div className="flex flex-col gap-4 p-4">{children}</div>
    </Card>
  )
}

function Row({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-2">{children}</div>
}

const NOW = Date.parse('2026-09-18T06:20:04Z')

/** 화면 기준 시각(#79)의 조회 하나. 몇 초 전에 받았는지 · 실패했는지만 바꿔 본다 */
function asOfPart(agoMs: number, failed = false) {
  return { dataUpdatedAt: NOW - agoMs, errorUpdatedAt: failed ? NOW - 1_000 : 0, isError: failed, asOf: NOW - agoMs }
}

/** 관제 이상 요약(사이드바 · 상단바)의 다섯 상태: 조회 전 · 확인 불가 · 이상 · 일부 미확인 · 이상 없음 */
const OPS_VIEWS: OpsView[] = [
  { state: 'pending' },
  { state: 'error' },
  {
    state: 'ok',
    alerts: [
      { key: 'loader', level: 'alert', label: '적재기', reason: '적재기 확인 중단 · 마지막 45분 전', at: null, count: null },
      { key: 'gateway_mismatch', level: 'alert', label: '관문 불일치', reason: null, at: null, count: 1 },
    ],
    unknowns: [],
  },
  { state: 'ok', alerts: [], unknowns: [{ key: 'nodes', level: 'unknown', label: '노드 수신', reason: '노드 표를 읽을 수 없음', at: null, count: null }] },
  { state: 'ok', alerts: [], unknowns: [] },
]

export function ComponentCatalog() {
  const [view, setView] = useState<'all' | 'origin' | 'segment' | 'rule'>('all')
  const [onlyBad, setOnlyBad] = useState(true)
  const [saving, setSaving] = useState(false)
  const release = permission('operator', 'block.release')
  const verdict = permission('operator', 'incident.verdict')

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="공통 컴포넌트"
        badges={<Badge tone="info">WBS 3.6.1</Badge>}
        description="atoms · molecules · 상태 화면. 개발 서버에서만 보이는 대조용 화면이다."
        aside={<span className="text-xs text-ink-muted">30초마다 갱신</span>}
        status={<AsOfStatus parts={[asOfPart(4_000)]} now={NOW} />}
      />

      <Banner tone="danger" title="데이터 연결이 끊겼습니다">
        마지막 수신 <Time value={NOW - 84_000} format="time" className="font-mono" /> (<Time value={NOW - 84_000} format="relative" now={NOW} />). 화면의 수치는 그 시점 기준입니다.
      </Banner>
      <Banner tone="warning" title="순환 규칙">
        규칙 조건과 판정 기준의 위협 조건이 같습니다.
      </Banner>

      <Section title="단추">
        <Row>
          <Button variant="primary">판정 기록</Button>
          <Button>수집 노드 보기</Button>
          <Button variant="ghost">담당 해제</Button>
          <Button variant="danger">차단 해제</Button>
          <Button variant="primary" loading={saving} onClick={() => setSaving(true)}>
            {saving ? '저장 중' : '눌러서 처리 중 보기'}
          </Button>
        </Row>
        <Row>
          <Button size="sm">조건 초기화</Button>
          <Button size="sm" variant="primary">
            로그인
          </Button>
          <Button size="lg" variant="primary">
            다시 연결
          </Button>
          <Button size="lg">수집 노드 보기</Button>
          <Button size="icon" aria-label="새로고침">
            ↻
          </Button>
        </Row>
        <Row>
          <Button disabled>이유 없는 비활성</Button>
          <Button variant="danger" disabled={!release.allowed} disabledReason={release.reason}>
            차단 해제 (operator)
          </Button>
          <Gated {...release} showReason>
            <Button variant="danger">규칙 억제 (Gated)</Button>
          </Gated>
          <Gated {...verdict}>
            <Button variant="primary">판정 (operator 허용)</Button>
          </Gated>
        </Row>
      </Section>

      <Section title="배지">
        <Row>
          {SEVERITIES.map((s) => (
            <SeverityBadge key={s} severity={s} />
          ))}
        </Row>
        <Row>
          {VERDICTS.map((v) => (
            <VerdictBadge key={v} verdict={v} />
          ))}
        </Row>
        <Row>
          <Badge tone="info">규칙 v2 기준</Badge>
          <Badge>v1 인시던트 117건 숨김</Badge>
          <Badge tone="success">정상</Badge>
          <Badge tone="violet">자기 탐지</Badge>
          <span className="inline-flex items-center gap-2 text-xs text-ink-muted">
            <StatusDot signal="bad" />
            데이터 연결 끊김
          </span>
          <Kbd>/</Kbd>
        </Row>
        {/* 관제 이상 요약(#72): 사이드바 글 · 모바일 상단바 짧은 글. 누르면 대시보드로 간다 */}
        <Row>
          {OPS_VIEWS.map((view, i) => (
            <OpsSummary key={`full-${i}`} view={view} />
          ))}
        </Row>
        <Row>
          {OPS_VIEWS.map((view, i) => (
            <OpsSummary key={`compact-${i}`} view={view} compact />
          ))}
        </Row>
        {/* CVE 배지(#52): 정보 색 · 둥근 테두리. 판정값 · 심각도 배지와 섞이지 않는다 */}
        <Row>
          <CtiBadge badge={{ cves: 2, kev: 1, applicability: 'affected', stale: false }} />
          <CtiBadge badge={{ cves: 3, kev: 0, applicability: 'not_affected', stale: false }} />
          <CtiBadge badge={{ cves: 1, kev: 1, applicability: 'unknown', stale: true }} />
          <CtiBadge badge={{ cves: 0, kev: 0, applicability: 'unknown', stale: false }} />
        </Row>
        {/* 도움말(ⓘ): 누르면 단추 가까이 말풍선으로 뜬다(하나만 열림) · '기준 보기' 는 인쇄에 펼쳐 찍힌다 */}
        <Row>
          <span className="text-sm">정탐률 <InfoTip label="정탐률">최근 30일 판정 가운데 위협으로 판정한 비율</InfoTip></span>
          <div><InfoTip variant="text" label="판정 품질" print="expand" panelAs="div">제안이 없던 판정은 뒤집힘으로 세지 않는다</InfoTip></div>
        </Row>
        {/* 화면 기준 시각(#79): 정상 · 오래됨 · 일부 실패 · 실패. 대시보드 · 장비 로그는 PageRefresh 로 새로고침과 함께 둔다 */}
        <Row>
          <AsOfStatus parts={[asOfPart(4_000)]} now={NOW} />
          <AsOfStatus parts={[asOfPart(185_000)]} now={NOW} />
          <AsOfStatus parts={[asOfPart(4_000), asOfPart(40_000, true)]} now={NOW} />
          <AsOfStatus parts={[asOfPart(40_000, true)]} now={NOW} />
        </Row>
      </Section>

      <Section title="비신뢰 문자열">
        <p className="m-0 text-xs text-ink-muted">로그 · 공격자 입력은 UntrustedText 로 그린다. 숨은 문자는 표식, 줄바꿈은 ↵, 값 전체는 방향 격리, 긴 값은 접는다.</p>
        <Row>
          <span className="text-sm">대상 <UntrustedText value={'user:admin\u{202E}gnp.exe'} /> · 뒤 필드</span>
          <span className="text-sm">
            계정 <UntrustedText value={'ad\u{200B}min'} />
          </span>
          <span className="font-mono text-xs">
            <UntrustedText value={'\u{1B}[31m빨강 \u{2066}x\u{2069} \u{FEFF}'} />
          </span>
        </Row>
        <p className="m-0 font-mono text-xs">
          input=<UntrustedText value={'ls\n2026-09-18 15:00:00 decoy login.success'} />
        </p>
        <p className="m-0 font-mono text-xs">
          <UntrustedText value={'A'.repeat(300)} max={80} />
        </p>
        <span className="block w-60 truncate text-sm" title="한 줄 말줄임(clip)">
          <UntrustedText value={`user:${'L'.repeat(120)}`} clip />
        </span>
      </Section>

      <Section title="입력">
        <Row>
          <SegmentedControl
            aria-label="묶음 기준"
            value={view}
            onChange={setView}
            options={[
              { value: 'all', label: '전체' },
              { value: 'origin', label: '발생원' },
              { value: 'segment', label: '세그먼트' },
              { value: 'rule', label: '규칙' },
            ]}
          />
          <Switch label="문제만 보기" checked={onlyBad} onChange={(e) => setOnlyBad(e.target.checked)} />
          <Chip onRemove={() => undefined} removeLabel="판정 = 미판정 조건 빼기">
            판정 = 미판정
          </Chip>
          <Input fieldSize="sm" type="search" placeholder="출발지 IP 또는 인시던트 키" aria-label="검색" className="w-60" />
        </Row>
        <div className="grid gap-4 md:grid-cols-3">
          <FormField label="출발지 차단" hint="만료가 있는 되돌릴 수 있는 조치입니다">
            {(f) => (
              <Select {...f} defaultValue="24">
                <option value="24">24시간</option>
                <option value="168">7일</option>
                <option value="720">30일</option>
              </Select>
            )}
          </FormField>
          <FormField label="판정 근거" required error="근거를 적어 주세요">
            {(f) => <Textarea {...f} placeholder="예: R002 위협 판정과 같은 세션, 새 정보 없음" />}
          </FormField>
          <FormField label="아이디">{(f) => <Input {...f} autoComplete="off" />}</FormField>
        </div>
      </Section>

      <div className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard tone="danger" label="가장 오래된 미판정" value="6시간 12분" caption="판정 목표 위반 2건 · 경고 1건" action={<a href="/incidents">해당 건 보기 ›</a>} />
        <StatCard label="미판정 잔량" value="23건" caption="폐루프 2회차 입력" action={<a href="/incidents">목록 보기 ›</a>} />
        <StatCard label="오늘 판정" value="9건" caption="건당 중앙 소요 2분 10초" />
        <StatCard label="제안 뒤집힘" value="—" loading />
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <EmptyState
          eyebrow="S-03 · 결과 0건"
          title="조건에 맞는 인시던트가 없습니다"
          description="조건 3개 적용 중. 미판정 0건은 좋은 소식이기 전에 수집부터 확인합니다."
          actions={
            <>
              <Button size="sm">조건 초기화</Button>
              <Button size="sm">수집 노드 보기</Button>
            </>
          }
        />
        <LoadingState eyebrow="S-03 · 불러오는 중" title="이전 결과를 유지한 채 조회합니다" description="새 조건으로 다시 조회하면 이전 요청은 취소합니다." />
        <ForbiddenState requiredRoles="admin" currentRole="operator" onBack={() => undefined} />
        <SessionExpiredState />
        <ErrorState error={new ApiError({ status: 503, detail: '데이터베이스에 연결할 수 없습니다' })} onRetry={() => undefined} />
        <NotFoundState path="/incidents/R999|v2|1.2.3.4" />
      </div>

      <ErrorState
        size="page"
        eyebrow="S-10 · 연결 끊김"
        title="데이터베이스에 연결할 수 없습니다"
        description="판정과 조치는 저장되지 않으니 잠시 기다려 주세요. 수집은 멈추지 않았고, 연결이 돌아오면 밀린 로그를 소급 적재합니다."
        icon={<IconDatabaseOff size={28} />}
        actions={
          <>
            <Button size="lg" variant="primary">
              다시 연결
            </Button>
            <Button size="lg">수집 노드 보기</Button>
          </>
        }
        footnote="열려 있던 판정 패널과 팝업은 닫고 이 화면으로 옵니다."
      />
    </div>
  )
}
