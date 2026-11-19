// The platform bundles the TypeScript application with its server dependencies.
process.env.NODE_ENV = "production";
process.env.INSIGHT_NETLIFY = "true";
const { createAttendanceApp } = await import("../../server.ts");
export const config = { path: "/api/*" };
export default await createAttendanceApp();
