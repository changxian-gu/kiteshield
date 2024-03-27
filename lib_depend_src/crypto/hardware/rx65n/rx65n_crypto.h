/**
 * @file rx65n_crypto.h
 * @brief RX65N hardware cryptographic accelerator (TSIP)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2023 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.4
 **/

#ifndef _RX65N_CRYPTO_H
#define _RX65N_CRYPTO_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Global variables
extern OsMutex rx65nCryptoMutex;

//RX65N hardware cryptographic accelerator related functions
error_t rx65nCryptoInit(void);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
