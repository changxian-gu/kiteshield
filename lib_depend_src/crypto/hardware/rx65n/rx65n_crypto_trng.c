/**
 * @file rx65n_crypto_trng.c
 * @brief RX65N true random number generator
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "r_tsip_rx_if.h"
#include "core/crypto.h"
#include "hardware/rx65n/rx65n_crypto.h"
#include "hardware/rx65n/rx65n_crypto_trng.h"
#include "debug.h"

//Check crypto library configuration
#if (RX65N_CRYPTO_TRNG_SUPPORT == ENABLED)


/**
 * @brief Get random data from the TRNG module
 * @param[out] data Buffer where to store random data
 * @param[in] length Number of random bytes to generate
 **/

error_t trngGetRandomData(uint8_t *data, size_t length)
{
   size_t i;
   size_t j;
   uint32_t value[4];
   e_tsip_err_t status;

   //Acquire exclusive access to the TSIP module
   osAcquireMutex(&rx65nCryptoMutex);

   //Generate random data
   for(i = 0; i < length; i++)
   {
      //Generate a new 128-bit random value when necessary
      if((i % 16) == 0)
      {
         //Get 128-bit random value
         status = R_TSIP_GenerateRandomNumber(value);
         //Check status code
         if(status != TSIP_SUCCESS)
         {
            break;
         }
      }

      //Extract a random byte
      j = (i % 16) / 4;

      //Copy random byte
      data[i] = value[j] & 0xFF;
      //Shift the 32-bit random value
      value[j] >>= 8;
   }

   //Release exclusive access to the TSIP module
   osReleaseMutex(&rx65nCryptoMutex);

   //Return status code
   return (status == TSIP_SUCCESS) ? NO_ERROR : ERROR_FAILURE;
}

#endif
