/*
 * Copyright (c) 2018 Guillem96
 * Copyright (c) 2018 CTCaer
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "core/launcher.h"

#include <string.h>

#include "libs/fatfs/ff.h"
#include "utils/types.h"
#include "utils/util.h"
#include "utils/fs_utils.h"
#include "gfx/gfx.h"
#include "soc/hw_init.h"
#include "mem/heap.h"
#include "menu/gui/gui_menu_pool.h"

// This is a safe and unused DRAM region for our payloads.
#define IPL_LOAD_ADDR      0x40008000
#define EXT_PAYLOAD_ADDR   0xC03C0000
#define PATCHED_RELOC_SZ   0x94
#define RCM_PAYLOAD_ADDR   (EXT_PAYLOAD_ADDR + ALIGN(PATCHED_RELOC_SZ, 0x10))
#define PAYLOAD_ENTRY      0x40010000
#define CBFS_SDRAM_EN_ADDR 0x4003e000
#define COREBOOT_ADDR      (0xD0000000 - 0x100000)

void (*ext_payload_ptr)() = (void *)EXT_PAYLOAD_ADDR;

void reloc_patcher(u32 payload_size)
{
	static const u32 START_OFF = 0x7C;
	static const u32 PAYLOAD_END_OFF = 0x84;
	static const u32 IPL_START_OFF = 0x88;

	memcpy((u8 *)EXT_PAYLOAD_ADDR, (u8 *)IPL_LOAD_ADDR, PATCHED_RELOC_SZ);

	*(vu32 *)(EXT_PAYLOAD_ADDR + START_OFF) = PAYLOAD_ENTRY - ALIGN(PATCHED_RELOC_SZ, 0x10);
	*(vu32 *)(EXT_PAYLOAD_ADDR + PAYLOAD_END_OFF) = PAYLOAD_ENTRY + payload_size;
	*(vu32 *)(EXT_PAYLOAD_ADDR + IPL_START_OFF) = PAYLOAD_ENTRY;

	if (payload_size == 0x7000)
	{
		memcpy((u8 *)(EXT_PAYLOAD_ADDR + ALIGN(PATCHED_RELOC_SZ, 0x10)), (u8 *)COREBOOT_ADDR, 0x7000); //Bootblock
		*(vu32 *)CBFS_SDRAM_EN_ADDR = 0x4452414D;
	}
}

int launch_payload(char *path)
{

    char *atm = "atmos";
    char *rnx = "reinx";
    char *sxos = "sxos";

    u32 boot = 0;



    if(strstr(path,atm) != NULL)
    	boot=1;
    if(strstr(path,rnx) != NULL)
    	boot=2;
    if(strstr(path,sxos) != NULL)
    	boot=3;

    u8* buffer = (u8*)malloc(4);
    memcpy(buffer, &boot, 4);
    sd_save_to_file(buffer, 4, "RR/boot.txt");
    if(boot==1)
    {
	copyfile("sept/ams/payload.bin","sept/payload.bin");
	copyfile("sept/ams/sept-primary.bin","sept/sept-primary.bin");
	copyfile("sept/ams/sept-secondary.bin","sept/sept-secondary.bin");
	copyfile("sept/ams/sept-secondary.enc","sept/sept-secondary.enc");

    }

    if(boot==2)
    {
	copyfile("sept/reinx/payload.bin","sept/payload.bin");
	copyfile("sept/reinx/sept-primary.bin","sept/sept-primary.bin");
	copyfile("sept/reinx/sept-secondary.bin","sept/sept-secondary.bin");
	copyfile("sept/reinx/sept-secondary.enc","sept/sept-secondary.enc");
    }

    clean_templates();


    FIL fp;
    if (f_open(&fp, path, FA_READ))
    {
        //gfx_printf(&g_gfx_con, "Cannot find %s\n", path);
        return 1;
    }

    // Read and copy the payload to our chosen address
    void *buf;
    u32 size = f_size(&fp);

    if (size < 0x30000)
        buf = (void *)RCM_PAYLOAD_ADDR;
    else
        buf = (void *)COREBOOT_ADDR;

    if (f_read(&fp, buf, size, NULL))
    {
        f_close(&fp);
        gfx_printf(&g_gfx_con, "Error loading %s\n", path);
        return 1;
    }

    f_close(&fp);	
    free(path);
    path = NULL;

    sd_unmount();

    if (size < 0x30000)
    {
        reloc_patcher(ALIGN(size, 0x10));
        reconfig_hw_workaround(false, byte_swap_32(*(u32 *)(buf + size - sizeof(u32))));
    }
    else
    {
        reloc_patcher(0x7000);
        if (*(vu32 *)CBFS_SDRAM_EN_ADDR != 0x4452414D)
            return 1;
        reconfig_hw_workaround(true, 0);
    }

    gui_menu_pool_cleanup();
    gfx_end_ctxt(&g_gfx_ctxt);
    
    // Launch our payload.
    (*ext_payload_ptr)();

	return 1;
}

int clean_templates()
{
    f_unlink("/atmosphere/titles/0100000000001000/romfs/lyt/common.szs");
    f_unlink("/atmosphere/titles/0100000000001000/romfs/lyt/Entrance.szs");
    f_unlink("/atmosphere/titles/0100000000001000/romfs/lyt/ResidentMenu.szs");
    f_unlink("/atmosphere/titles/0100000000001000/romfs/lyt/Set.szs");
    f_unlink("/atmosphere/titles/0100000000001000/romfs/lyt/Flaunch.szs");
    f_unlink("/atmosphere/titles/0100000000001000/romfs/lyt/Notification.szs");
    f_unlink("/atmosphere/titles/0100000000001000/fsmitm.flag");

    f_unlink("/ReiNX/titles/0100000000001000/romfs/lyt/common.szs");
    f_unlink("/ReiNX/titles/0100000000001000/romfs/lyt/Entrance.szs");
    f_unlink("/ReiNX/titles/0100000000001000/romfs/lyt/ResidentMenu.szs");
    f_unlink("/ReiNX/titles/0100000000001000/romfs/lyt/Set.szs");
    f_unlink("/ReiNX/titles/0100000000001000/romfs/lyt/Flaunch.szs");
    f_unlink("/ReiNX/titles/0100000000001000/romfs/lyt/Notification.szs");
    f_unlink("/ReiNX/titles/0100000000001000/fsmitm.flag");


    f_unlink("/SXOS/titles/0100000000001000/romfs/lyt/common.szs");
    f_unlink("/SXOS/titles/0100000000001000/romfs/lyt/Entrance.szs");
    f_unlink("/SXOS/titles/0100000000001000/romfs/lyt/ResidentMenu.szs");
    f_unlink("/SXOS/titles/0100000000001000/romfs/lyt/Set.szs");
    f_unlink("/SXOS/titles/0100000000001000/romfs/lyt/Flaunch.szs");
    f_unlink("/SXOS/titles/0100000000001000/romfs/lyt/Notification.szs");
    f_unlink("/SXOS/titles/0100000000001000/fsmitm.flag");

    return 0;
}
