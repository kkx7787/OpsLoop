// 조사용 시험(micro.test.tsx)을 콘솔 설정 그대로, 콘솔 폴더 밖에서 돌린다. 파일 읽기 허용만 저장소 전체로 넓힌다.
import { mergeConfig } from 'vitest/config'
import base from '../../../../../console/vite.config.ts'

export default mergeConfig(base, { server: { fs: { allow: ['/Users/hanseongmin/opsloop-repo'] } } })
