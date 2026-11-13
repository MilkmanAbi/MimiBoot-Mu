
/* End-to-end Night extensions; included here to reuse the NOR/payload harness. */
static uint32_t night_test_caps;
static mb_topology_t prepared;
static uint32_t test_caps(void){return night_test_caps;}
static int test_prepare(mb_topology_t t){prepared=t;return MB_OK;}
static mb_control_request_t request(unsigned action){mb_control_request_t q={0};q.version=1;q.size=sizeof q;q.action=action;return q;}
static void submit_reboot(void*v){mb_control_reboot(&sim_port,v);}
static void test_night(void){
 printf("Night: GRUB grammar, OS control, stable IDs, CPU pairs, fault injection\n");
 sim_reset();sim_port.arch=MB_ARCH_ARM;sim_port.capabilities=test_caps;sim_port.prepare_topology=test_prepare;
 night_test_caps=MB_CAP_CONTROL|MB_CAP_CONFIG|MB_CAP_ARM|MB_CAP_RAM|MB_CAP_XIP;
 const char*cfg="set default=mainos\nset timeout=5\nmenuentry mainos \"Main OS\" {\n slot ab\n topology arm arm\n args init=/sbin/init\n}\nmenuentry rescue \"Recovery\" {\n slot g\n}\n";
 mb_config_t c;char err[128];
 CHECK(mb_config_parse(&sim_port,cfg,strlen(cfg),&c,err,sizeof err)==MB_OK&&!c.errors&&c.n==2&&c.def==0&&c.timeout_s==5&&!strcmp(c.e[0].args,"init=/sbin/init"),"GRUB config preserves title, order and args");
 CHECK(mb_config_validate_save(&sim_port,cfg,strlen(cfg),err,sizeof err)==MB_OK,"strict config save");
 const char*bad[]={"menuentry x \"X\" {\nslot a\n", "menuentry x \"X\" {\nmenuentry y \"Y\" {\n}\n}\n", "menuentry x \"X\" {\nslot a\n}\nmenuentry x \"Again\" {\nslot b\n}\n", "set default=no-such-entry\nmenuentry x \"X\" {\nslot a\n}\n", "menuentry x \"X\" {\nslot a\ntopology arm riscv\n}\n", "menuentry x \"X\" {\nslot a\nexec arbitrary\n}\n"};
 uint32_t ops=sim.ops;
 for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++)CHECK(mb_config_validate_save(&sim_port,bad[i],strlen(bad[i]),err,sizeof err)!=MB_OK,"invalid config %u refused",i);
 CHECK(sim.ops==ops,"invalid config performs zero writes");
 mb_config_load(&sim_port,&c);CHECK(c.n==2&&!strcmp(c.e[c.def].name,"mainos"),"invalid save leaves prior config");
 CHECK(mb_config_set_default(&sim_port,"rescue")==MB_OK,"change default by name");
 mb_config_load(&sim_port,&c);CHECK(!strcmp(c.e[c.def].name,"rescue")&&!strcmp(c.e[0].args,"init=/sbin/init"),"default edit preserves entries");
 CHECK(mb_config_validate_save(&sim_port,"entry a\nslot a",14,err,sizeof err)==MB_OK&&mb_config_set_default(&sim_port,"a")==MB_OK,"editor accepts final line without newline");
 CHECK(mb_config_validate_save(&sim_port,cfg,strlen(cfg),err,sizeof err)==MB_OK,"restore config");
 mb_control_request_t q=request(MB_CONTROL_ENTRY);strcpy(q.entry,"mainos");q.topology=(mb_topology_t){MB_ARCH_ARM,MB_ARCH_RISCV,0};
 ops=sim.ops;CHECK(mb_control_submit(&sim_port,&q)==MB_E_UNSUPP&&sim.ops==ops,"M0 rejects mixed profile before writing");
 q.topology=(mb_topology_t){0};strcpy(q.entry,"missing");CHECK(mb_control_submit(&sim_port,&q)==MB_E_BADARG&&sim.ops==ops,"missing entry cannot reboot or write");
 q=request(MB_CONTROL_CONFIG);CHECK(mb_control_submit(&sim_port,&q)==MB_OK,"queue config mode");
 mb_bcl_t b;mb_bcl_load(&b,&sim_port);mb_slot_info_t info[MB_MAX_SLOTS];mb_plan_t plan;mb_config_load(&sim_port,&c);
 mb_decide(&sim_port,&b,&c,info,0,&plan);CHECK(plan.choice.config_mode&&plan.choice.want_menu&&plan.base.request==MB_REQ_NONE,"config request opens shell even without an image");
 mb_bcl_commit(&b,&plan.base);mb_decide(&sim_port,&b,&c,info,0,&plan);CHECK(!plan.choice.config_mode,"request consumed exactly once");
 b.cur.request=MB_REQ_NIGHT;memset(b.cur.reserved,0,sizeof b.cur.reserved);mb_bcl_commit(&b,&b.cur);mb_decide(&sim_port,&b,&c,info,0,&plan);
 CHECK(plan.choice.config_mode&&plan.choice.control_error==MB_E_CORRUPT&&plan.base.request==MB_REQ_NONE,"unknown control extension fails into config shell");
 install_raw(MB_SLOT_A,"MainOS",MB_VERSION(1,0,0),1,9,5000);install_raw(MB_SLOT_GOLDEN,"rescue",MB_VERSION(1,0,0),0,10,4000);
 q=request(MB_CONTROL_ENTRY);strcpy(q.entry,"mainos");strcpy(q.args,"init=/sbin/init test=1");CHECK(mb_control_submit(&sim_port,&q)==MB_OK,"queue named entry");
 const char*reordered="default rescue\nentry rescue\nslot g\nentry mainos\nslot ab\n";
 CHECK(mb_config_validate_save(&sim_port,reordered,strlen(reordered),err,sizeof err)==MB_OK,"reorder menu after request");
 CHECK(boot()==MB_SLOT_A&&log_now().last_entry==1,"pending named request survives entry reorder");
 CHECK(prepared.core0==MB_ARCH_ARM&&prepared.core1==MB_ARCH_ARM,"homogeneous pair prepared before launch");
 // Mixed Arm/RISC-V: resolve primary from image, leave secondary to OS startup.
 night_test_caps|=MB_CAP_RISCV|MB_CAP_MIXED|MB_CAP_ARCH_SWITCH;
 q=request(MB_CONTROL_ENTRY);strcpy(q.entry,"mainos");q.topology=(mb_topology_t){MB_ARCH_ARM,MB_ARCH_RISCV,0};
 CHECK(mb_control_submit(&sim_port,&q)==MB_OK&&boot()==MB_SLOT_A&&prepared.core1==MB_ARCH_RISCV,"mixed pair reaches launch");
 // Reboot into the RISC-V half first, retaining the mixed request and command line.
 make_payload(11,6000);mb_image_hdr_t rv=make_header_ex("RV",MB_VERSION(1,0,0),0,6000,0,MB_ARCH_RISCV,MB_LOAD_CHAIN,0,0);put_image(3,&rv);
 const char*rv_cfg="entry rv\nslot c\nentry mainos\nslot ab\n";mb_config_validate_save(&sim_port,rv_cfg,strlen(rv_cfg),err,sizeof err);
 sim.universal=true;q=request(MB_CONTROL_ENTRY);strcpy(q.entry,"rv");strcpy(q.args,"mixed=yes");q.topology=(mb_topology_t){MB_ARCH_RISCV,MB_ARCH_ARM,0};
 CHECK(mb_control_submit(&sim_port,&q)==MB_OK&&sim_power_on()==SIM_REBOOT&&sim.arch==MB_ARCH_RISCV,"mixed primary change performs loader handover");
 CHECK(log_now().request==MB_REQ_NIGHT&&!strcmp(log_now().args,"mixed=yes"),"handover retains extended request");
 CHECK(boot()==3&&prepared.core0==MB_ARCH_RISCV&&prepared.core1==MB_ARCH_ARM,"other loader half applies exact mixed pair");
 // New API negotiation: an old/absent handoff must not write a Night command.
 mb_client_init(&sim_port);ops=sim.ops;q=request(MB_CONTROL_MENU);CHECK(mb_client_control(&q,false)==MB_E_UNSUPP&&sim.ops==ops,"new control refuses missing capability negotiation");
 CHECK(mb_client_set_config(cfg,strlen(cfg),err,sizeof err)==MB_E_UNSUPP&&mb_client_set_default("rv")==MB_E_UNSUPP&&sim.ops==ops,"config writes also require new loader negotiation");
 // A real RAM launch produces a capability-bearing handoff, allowing identity
 // adoption without physical XIP mapping and preserving existing confirmation.
 make_payload(17,6000);mb_image_hdr_t rh=make_header_ex("ram-os",MB_VERSION(1,0,0),1,6000,0,MB_ARCH_RISCV,MB_LOAD_RAM,SIM_RAM_BASE,SIM_RAM_BASE+0x18000);put_image(MB_SLOT_A,&rh);
 const char*ramcfg="entry ram\nslot ab\n";mb_config_validate_save(&sim_port,ramcfg,strlen(ramcfg),err,sizeof err);
 CHECK(boot()==MB_SLOT_A&&sim.booted_ram,"RAM image launches with Night handoff");
 sim.self_slot=MB_SLOT_NONE;mb_client_init(&sim_port);volatile mb_handoff_t *hh=(volatile mb_handoff_t*)(sim_ram+0x18000);mb_client_set_handoff(hh);
 CHECK(mb_client_handoff()!=NULL&&(mb_client_capabilities()&MB_CAP_MIXED)&&mb_client_handoff()->slot==MB_SLOT_A,"RAM identity and capability negotiation validated against boot record");
 CHECK(mb_client_confirm()==MB_OK&&log_now().slot[MB_SLOT_A].state==MB_ST_GOOD,"RAM OS can confirm its own trial");
 q=request(MB_CONTROL_CONFIG);CHECK(mb_client_control(&q,false)==MB_OK,"negotiated client queues control");
 // Atomicity: every interrupted request update recovers either old or new request.
 sim.arch=MB_ARCH_ARM;sim_port.arch=MB_ARCH_ARM;
 q=request(MB_CONTROL_MENU);mb_control_submit(&sim_port,&q);
 static uint8_t saved[SIM_FLASH_SIZE];memcpy(saved,sim_flash,sizeof saved);
 q=request(MB_CONTROL_CONFIG);sim.cut_at=0;ops=sim.ops;mb_control_submit(&sim_port,&q);uint32_t count=sim.ops-ops;
 for(uint32_t cut=1;cut<=count;cut++){memcpy(sim_flash,saved,sizeof saved);sim.ops=0;sim.cut_at=cut;sim_guard(submit_reboot,&q);sim.cut_at=0;mb_bcl_load(&b,&sim_port);mb_topology_t top;int action=-1;mb_config_load(&sim_port,&c);int rc=mb_control_consume(&sim_port,&b.cur,&c,&top,&action);CHECK(rc==1&&(action==MB_CONTROL_MENU||action==MB_CONTROL_CONFIG),"request power cut %lu recovers old or new",(unsigned long)cut);}
 memcpy(sim_flash,saved,sizeof saved);sim.fail_writes=true;CHECK(sim_guard(submit_reboot,&q)!=SIM_REBOOT,"failed request commit never reboots");sim.fail_writes=false;
 CHECK(sizeof(mb_handoff_t)==160&&sizeof(mb_bcl_rec_t)==256,"legacy disk and handoff sizes retained");
 sim_port.capabilities=NULL;sim_port.prepare_topology=NULL;sim_reset();
}
