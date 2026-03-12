/** @type {import('next').NextConfig} */
const nextConfig = {
    // API 라우트 및 서버 액션의 파일 업로드 용량 제한을 50MB로 확장
    api: {
        bodyParser: {
            sizeLimit: '50mb',
        },
    },
    // Next.js Server Actions 사용 시 용량 제한 설정
    serverActions: {
        bodySizeLimit: '50mb',
    },

    // --- [핵심 수정] 외부 접속 및 CORS 보안 설정 ---
    experimental: {
        // 외부 IP나 도메인에서 접속 시 'Invalid Host Header' 에러 방지
        allowedDevOrigins: ["http://220.117.246.7:3000"],
    },

    // 개발 시 소스 맵 생성 등 추가 설정이 필요하면 여기에 넣습니다.
};

export default nextConfig;