/*
*
* Copyright (c) 2009-2011
* vol4ok <admin@vol4ok.net> PGP KEY ID: 26EC143CCDC61C9D
*

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DEFINES_
#define _DEFINES_

typedef unsigned long long	u64;
typedef unsigned long		u32;
typedef unsigned short		u16;
typedef unsigned char		u8;

typedef long long			s64;
typedef int					s32;
typedef short				s16;
typedef char				s8;
typedef const char			cs8;
typedef const u8			cu8;

#if defined(_WIN64)
typedef	long long			s3264;
typedef unsigned long long	u3264;
#else
typedef long				s3264;
typedef unsigned long		u3264;
#endif

#define p8(x)  ((u8*)(x))
#define pcu8(x) ((cu8*)(x))
#define p16(x) ((u16*)(x))
#define p32(x) ((u32*)(x))
#define p64(x) ((u64*)(x))
#define p3264(x) ((u3264*)(x))
#define pv(x)  ((void*)(x))
#define ppv(x) ((void**)(x))

#ifdef _DEBUG
#define dbg_msg DbgPrint
#else
#define dbg_msg
#endif

#define lock_inc(x)             ( _InterlockedIncrement(x) )
#define lock_dec(x)             ( _InterlockedDecrement(x) )
#define lock_xchg(p,v)          ( _InterlockedExchange((p),(v)) )
#define lock_cmpxchg(a,b,c)     ( _InterlockedCompareExchange((a),(b),(c)) )
#define lock_cmpxchg_ptr(a,b,c) ( pv(_InterlockedCompareExchange(pv(a),(u32)(b),(u32)(c))) )

#endif /* _DEFINES_ */