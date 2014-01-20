/* radare - LGPL - Copyright 2013-2014 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include <string.h>
#include "snes_op_table.h"

static int snesDisass(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len)
{
	int bits, n;

	switch(snes_op[buf[0]].type)
	{
		case SNES_OP_8BIT:
			if (len < 1)
				return 0;
			sprintf(op->buf_asm,"%s",snes_op[buf[0]].name);
			return 1;
		case SNES_OP_16BIT:
			if (len < 2)
				return 0;
			if (buf[0]==0xe2) {
				if (buf[1] & 0x20) {
					// SEP M-flag = go to 8bit
					r_asm_set_bits(a, 8);
				}
				// TODO: track X flag (0x10) too
			} else if(buf[0]==0xc2) {
				if (buf[1] & 0x20) {
					// REP M-flag = go to 16bit
					r_asm_set_bits(a, 16);
				}
				// TODO: track X flag (0x10) too
			}
			sprintf(op->buf_asm,snes_op[buf[0]].name,buf[1]);
			return 2;
		case SNES_OP_24BIT:
		case SNES_OP_24BIT_2ARG:
			if (len < 3)
				return 0;
			//sprintf(op->buf_asm, snes_op[buf[0]].name,buf[1]+0x100*buf[2]);
			sprintf(op->buf_asm, snes_op[buf[0]].name,buf[2],buf[1]);
			return 3;
		case SNES_OP_24BIT_M:
			bits = (a->bits == 8) ? 8 : 16;

			if (len < 1 + bits/8)
				return 0;
			n = sprintf(op->buf_asm, snes_op[buf[0]].name);
			switch(bits)
			{
				case 8:
					sprintf(op->buf_asm + n, "%02x", buf[1]);
					return 2;
				case 16:
					sprintf(op->buf_asm + n, "%02x%02x", buf[2], buf[1]);
					return 3;
			}
			return 1;
		case SNES_OP_24BIT_X:
			// Assume 16-bit X/Y for now
			if (len < 3)
				return 0;
			n = sprintf(op->buf_asm, "%s", snes_op[buf[0]].name);
			sprintf(op->buf_asm + n, "%02x%02x", buf[2], buf[1]);
			return 3;
		case SNES_OP_32BIT:
			if (len < 4)
				return 0;
			sprintf (op->buf_asm, snes_op[buf[0]].name,buf[1]+0x100*buf[2]+0x10000*buf[3]);
			return 4;
		default:
			return 0;
	}
}
