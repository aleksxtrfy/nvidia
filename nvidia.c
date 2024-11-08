DriverInformation_t NVBase;
	uint32_t UuidValidOffset = 0;

	// Get nvlddmkm.sys information.
	if (!Utils::GetDriverInformation(H("nvlddmkm.sys"), NVBase))
	{
		DBG("Could not find nvlddmkm.sys\n");
		return 0;
	}

	// Search for pattern.
	uint64_t Addr = Utils::FindPattern(NVBase.BaseAddress, "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x0F\x84\xCC\xCC\xCC\xCC\x44\x8B\x80\xCC\xCC\xCC\xCC\x48\x8D\x15");

	// Pattern not found or incorrect match.
	if (!Addr || *(uint8_t*)(Addr + 0x3B) != 0xE8)
	{
		DBG("Could not find pattern\n");
		return 0;
	}

	// Resolve reference.
	uint64_t(*GpuMgrGetGpuFromId)(int) = decltype(GpuMgrGetGpuFromId)(*(int*)(Addr + 1) + 5 + Addr);

	Addr += 0x3B; 
	
	// gpuGetGidInfo
	Addr += *(int*)(Addr + 1) + 5;

	// Walk instructions to find GPU::gpuUuid.isInitialized offset.
	for (int InstructionCount = 0; InstructionCount < 50; InstructionCount++)
	{
		hde64s HDE;
		hde64_disasm((void*)Addr, &HDE);

		// Did HDE fail to disassemble the instruction?
		if (HDE.flags & F_ERROR)
		{
			DBG("Failed to disassemble %p\n", Addr);
			return 0;
		}

		// cmp [rcx + GPU::gpuUuid.isInitialized], dil
		uint32_t Opcode = *(uint32_t*)Addr & 0xFFFFFF;
		if (Opcode == 0xB93840)
		{
			UuidValidOffset = *(uint32_t*)(Addr + 3);
			break;
		}

		// Increment instruction pointer.
		Addr += HDE.len;
	}

	// Could not find GPU::gpuUuid.isInitialized offset
	if (!UuidValidOffset)
	{
		DBG("Failed to find offset\n");
		return 0;
	}

	// Max number of GPUs supported is 32.
	for (int i = 0; i < 32; i++)
	{
		uint64_t ProbedGPU = GpuMgrGetGpuFromId(i);
		
		// Does not exist?
		if (!ProbedGPU) continue;

		// Is GPU UUID not initialized?
		if (!*(bool*)(ProbedGPU + UuidValidOffset)) continue;

		// UuidValid + 1 = UUID
		// You can use your own randomization process here, but I use the TSC timestamp because it's easier.
		for (int j = 0; j < sizeof(UUID); j++)
			*(uint8_t*)(ProbedGPU + UuidValidOffset + 1 + j) = __rdtsc();

		DBG("Spoofed GPU %d\n", i);
	}