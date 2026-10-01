static void armFull(void){
    if(!g_targetBase) return;
    @try{
        uintptr_t g = kSessionBaseFile;
        uint64_t now_ms  = boot_ms();
        uint64_t now_sec = now_ms / 1000;

        // 只写门卫，暂不写会话对象
        w64(g+0x6a0, CFG_C ^ now_ms);
        writeGateTriple(g+0x6a0);
        w64(g+0x680, CFG_C ^ now_sec);
        writeGateTriple(g+0x680);

        // 注释掉会话对象
        // w64(g+0x698, (uintptr_t)buildSessionObj());

        g_armDone = 1;
    }@catch(NSException*e){}
}
