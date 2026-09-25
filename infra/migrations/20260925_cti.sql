-- CVE · KEV 연계 (이슈 #39). schema.sql 의 'CVE · KEV 연계' 블록과 동일하며 여러 번 적용해도 같다.
--   역할 블록(schema.sql · 20260924_db_roles.sql) 뒤에 적용한다. 역할 블록은 콘솔 역할의 모든 표 권한을 먼저 거두므로
--   역할 블록을 다시 적용하면 콘솔의 CTI 표 읽기가 사라진다. 그때는 이 파일도 다시 적용한다.
--   opsloop_cti 역할은 cti/install-cti.sh 가 만든다.
BEGIN;
-- CVE · KEV 연계 (이슈 #39)
--   공개 취약점 정보(CISA KEV · EPSS · OSV · NVD)와 자산 조사 결과를 정리해 둔다. 원본은 데이터 노드 수집기(opsloop-cti)가
--   S3 cti/ 에 한 번만 쓰고, 여기에는 정규화한 행과 원본 위치(s3_key · sha256)만 둔다. 원본을 S3 에 남기지 못한 회차는
--   DB 도 갱신하지 않는다(그날 무엇을 보고 판단했는지 원본으로 재현할 수 있어야 한다).
--   CVE · KEV · EPSS · CVSS 는 판정값이 아니라 조사 우선순위 정보다. 탐지는 이 표를 읽지 않는다(규칙 c1 은 요청 경로만 본다).
--   수집기 역할(opsloop_cti)이 쓰고 콘솔 역할이 읽는다. 원본 기록(cti_snapshots)은 추가만 된다.
--   infra/migrations/20260925_cti.sql 이 이 블록과 같다. 역할 블록이 모든 표의 권한을 먼저 거두므로 권한은 여기서 다시 준다.
--   역할 블록 뒤에 있어야 하고, 역할 블록을 다시 적용하면 이 블록도 다시 적용한다.
CREATE TABLE IF NOT EXISTS cti_snapshots (
    id              bigserial   PRIMARY KEY,
    source          text        NOT NULL CHECK (source IN ('kev', 'epss', 'osv', 'nvd', 'assets')),
    fetched_at      timestamptz NOT NULL DEFAULT now(),
    source_url      text,
    source_ts       timestamptz,          -- 원천이 밝힌 기준 시각 (KEV dateReleased · EPSS score_date · 자산 수집 시각)
    source_version  text,                 -- KEV catalogVersion · EPSS model_version
    s3_key          text,                 -- 원본 위치. 원본을 못 남긴 회차는 NULL
    sha256          text        CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    bytes           bigint      CHECK (bytes >= 0),
    records         integer,
    status          text        NOT NULL CHECK (status IN ('ok', 'failed')),
    error           text,
    CONSTRAINT cti_snapshots_s3_key_ok CHECK ((status = 'ok') = (s3_key IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_cti_snapshots_source ON cti_snapshots (source, fetched_at DESC);

-- 실제로 악용된 취약점 목록 (CISA KEV). 목록과 같게 유지한다(빠진 항목은 지운다).
CREATE TABLE IF NOT EXISTS cti_kev (
    cve_id          text        PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    vendor_project  text        NOT NULL,
    product         text        NOT NULL,
    name            text        NOT NULL,
    description     text,
    date_added      date        NOT NULL,
    due_date        date,
    ransomware      text,                 -- Known · Unknown
    snapshot_id     bigint      NOT NULL REFERENCES cti_snapshots (id)
);

-- CVE 하나의 악용 가능성(EPSS)과 심각도(NVD CVSS). 관심 CVE(KEV · 자산 · 서명 · 주목 CVE)만 둔다.
CREATE TABLE IF NOT EXISTS cti_cve (
    cve_id           text         PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    epss             real         CHECK (epss BETWEEN 0 AND 1),
    epss_percentile  real         CHECK (epss_percentile BETWEEN 0 AND 1),
    epss_date        date,
    epss_snapshot_id bigint       REFERENCES cti_snapshots (id),
    cvss_score       numeric(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_version     text,
    cvss_vector      text,
    cvss_severity    text,
    description      text,
    published        timestamptz,
    nvd_status       text,
    nvd_fetched_at   timestamptz,
    nvd_snapshot_id  bigint       REFERENCES cti_snapshots (id)
);

-- 배포판 취약점 기록 (OSV 의 Ubuntu 생태계). 배포판은 보안 수정을 옛 버전 번호에 덧대어 내보내므로
--   해당 여부는 업스트림 버전이 아니라 이 기록의 수정 버전(fixed)으로 판단한다. fixed 는 수정판이 있는 항목만,
--   affected 는 수정판이 없는 항목(null)까지 영향 항목을 모두 담는다.
CREATE TABLE IF NOT EXISTS cti_osv (
    osv_id          text        PRIMARY KEY,            -- UBUNTU-CVE-2024-6387
    cve_id          text,                               -- upstream 첫 CVE
    modified        timestamptz,
    detailed        boolean     NOT NULL DEFAULT false, -- 상세 기록을 받았는지 (아니면 id · modified 만)
    ubuntu_priority text,                               -- negligible · low · medium · high · critical
    cvss_vector     text,
    summary         text,                               -- details 앞 500자
    fixed           jsonb       NOT NULL DEFAULT '{}',  -- {"Ubuntu:24.04:LTS/openssh": "1:9.6p1-3ubuntu13.3"}
    affected        jsonb       NOT NULL DEFAULT '{}',  -- {"Ubuntu:24.04:LTS/linux": null} 수정판이 없으면 null
    snapshot_id     bigint      NOT NULL REFERENCES cti_snapshots (id)
);
CREATE INDEX IF NOT EXISTS idx_cti_osv_cve ON cti_osv (cve_id);

-- 주목 CVE. 널리 알려진 CVE 몇 개(cti/watchlist.json)를 자산마다 배포판 수정판과 비교해 해당 여부를 보인다.
--   asset_vulnerabilities 는 걸린 것만 담으므로, 이미 고쳐진(비해당) CVE 의 근거는 이 표와 cti_osv.affected 에서
--   나온다. 목록 파일과 같게 유지한다(빠진 CVE 는 지운다).
CREATE TABLE IF NOT EXISTS cti_watch (
    cve_id          text        PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    reason          text        NOT NULL,
    osv_id          text        REFERENCES cti_osv (osv_id), -- 배포판 기록 (없으면 NULL)
    record_found    boolean,                                 -- NULL 조회 전 · true 기록 있음 · false 기록 없음(404)
    checked_at      timestamptz,
    snapshot_id     bigint      REFERENCES cti_snapshots (id)
);

-- 자산 조사 결과. 자산은 관제 대상 · 관제 기반 · 센서 호스트이고 nodes(수집 에이전트 등록)와 따로 둔다.
--   조사가 실패하면 옛 결과를 그대로 두고 시도 기록(last_attempt_at · last_error)만 고친다. 오래된 결과는
--   콘솔이 '미확인'으로 보인다(취약점 없음이 아니다).
CREATE TABLE IF NOT EXISTS asset_inventory (
    asset_id          text        PRIMARY KEY CHECK (asset_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    role              text        NOT NULL CHECK (role IN ('target', 'platform', 'sensor')),
    method            text        NOT NULL CHECK (method IN ('ssh', 'ssm')),
    host              text,                 -- 호스트명 또는 인스턴스 ID
    collected_at      timestamptz,          -- 마지막으로 성공한 조사 시각 (노드가 적은 시각)
    received_at       timestamptz,          -- 적재기가 그 조사를 받은 시각
    os                jsonb,
    kernel            jsonb,
    packages          jsonb       NOT NULL DEFAULT '[]',
    images            jsonb       NOT NULL DEFAULT '[]',
    probe_errors      jsonb       NOT NULL DEFAULT '[]',
    snapshot_id       bigint      REFERENCES cti_snapshots (id),
    last_attempt_at   timestamptz NOT NULL DEFAULT now(),
    last_error        text,                 -- 마지막 시도가 실패한 이유
    checked_at        timestamptz,          -- 배포판 취약점(OSV) 대조를 마친 시각
    check_snapshot_id bigint      REFERENCES cti_snapshots (id),
    check_error       text
);

-- 자산별 배포판 취약점. 대조할 때마다 자산 단위로 지우고 다시 넣는다.
CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
    asset_id        text        NOT NULL REFERENCES asset_inventory (asset_id),
    source_package  text        NOT NULL,   -- 소스 패키지 (커널은 실행 중 커널의 소스: linux · linux-aws 등)
    version         text        NOT NULL,   -- 대조한 소스 버전 (커널은 실행 중인 커널 패키지 버전)
    osv_id          text        NOT NULL REFERENCES cti_osv (osv_id),
    cve_id          text,
    fix_state       text        NOT NULL
                    CHECK (fix_state IN ('fix_available', 'reboot_pending', 'no_fix', 'unknown')),
    fixed_version   text,
    snapshot_id     bigint      NOT NULL REFERENCES cti_snapshots (id),
    PRIMARY KEY (asset_id, source_package, osv_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_vulnerabilities_cve ON asset_vulnerabilities (cve_id);

-- 수집기 역할(opsloop_cti)은 이 표들만 쓰고, 콘솔 역할은 읽기만 한다. 역할은 여기서 만들지 않는다(cti/install-cti.sh).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_cti') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_cti', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_cti;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_cti;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_cti;
        GRANT SELECT, INSERT ON cti_snapshots TO opsloop_cti;                 -- 원본 기록은 추가만 (S3 한 번 쓰기와 같은 뜻)
        GRANT USAGE ON SEQUENCE cti_snapshots_id_seq TO opsloop_cti;
        GRANT SELECT, INSERT, UPDATE, DELETE ON cti_kev TO opsloop_cti;       -- 목록에서 빠진 항목을 지운다
        GRANT SELECT, INSERT, UPDATE ON cti_cve, cti_osv TO opsloop_cti;
        GRANT SELECT, INSERT, UPDATE, DELETE ON cti_watch TO opsloop_cti;     -- 목록 파일에서 빠진 CVE 를 지운다
        GRANT SELECT, INSERT, UPDATE ON asset_inventory TO opsloop_cti;       -- 조사가 실패하면 시도 기록만 고친다
        GRANT SELECT, INSERT, DELETE ON asset_vulnerabilities TO opsloop_cti; -- 자산마다 다시 계산한다
        GRANT SELECT ON rule_versions TO opsloop_cti;                         -- url_signature 서명의 CVE · KEV 조건
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT SELECT ON cti_snapshots, cti_kev, cti_cve, cti_osv, cti_watch,
                        asset_inventory, asset_vulnerabilities TO opsloop_console;
    END IF;
END
$$;
COMMIT;
