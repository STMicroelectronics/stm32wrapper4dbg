/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause */
/*
 * Copyright (c) 2024, STMicroelectronics - All Rights Reserved
 * Author: Antonio Borneo <antonio.borneo@foss.st.com>
 */

/*
 * This file is used to add the label 'fsbl_ptr' at the end of an assembly
 * file. The label will be used as it was one of the 'literals' of the last
 * function of the assembly file, thus allowing PC relative loading of the
 * data at the label's address.
 */

#include ASM_FILE

	.text
	.align	2
fsbl_ptr:
