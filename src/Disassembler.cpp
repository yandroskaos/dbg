#include "Disassembler.h"

#include "./distorm/distorm.h"
#include "./distorm/mnemonics.h"

#ifdef _WIN64
#pragma comment(lib, "../src/distorm/distorm64.lib")
#else
#pragma comment(lib, "../src/distorm/distorm32.lib")
#endif

UINT DasmInstSize(LPVOID _code, UINT _size, UINT _mode)
{
	_DecodedInst instructions[1];
	unsigned int decodedInstructionsCount = 0;

	_DecodeResult res = distorm_decode(0,	(const unsigned char*)_code, _size,
		_mode == 32 ? Decode32Bits : Decode64Bits,
		instructions, 1, &decodedInstructionsCount);
	
	return instructions[0].size;
}
