# [SCSSU-201801](https://smartcardservices.github.io/security/)

## Vulnerable Code Path

The vulnerable code is located in [`Tokend/CAC/CACRecord.cpp` of smartcardservices](https://github.com/smartcardservices/smartcardservices/blob/b8a17554d438eeb7e4588f3af1d6aa6651289026/Tokend/CAC/CACRecord.cpp#L58-L104) and was fixed with commit [`785856`](https://github.com/smartcardservices/smartcardservices/commit/785856ad318579607da0f7ad5129aed9e6e5ab75).

```cpp
    [...]
    unsigned char result[MAX_BUFFER_SIZE];
	size_t resultLength = sizeof(result);
    [...]
	try
	{
		PCSC::Transaction _(cacToken);
		cacToken.select(mApplication);
		uint32_t cacreturn;
		do
		{
			cacreturn = cacToken.exchangeAPDU(command, sizeof(command), result,
				resultLength);

			if ((cacreturn & 0xFF00) != 0x6300)
				CACError::check(cacreturn);

			size_t requested = command[4];
			if (resultLength != requested + 2)
                PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);

			memcpy(certificate + certificateLength, result, resultLength - 2);
			certificateLength += resultLength - 2;
			// Number of bytes to fetch next time around is in the last byte
			// returned.
			command[4] = cacreturn & 0xFF;
		} while ((cacreturn & 0xFF00) == 0x6300);
	}
	catch (...)
	{
		return NULL;
	}
```

The issue here is that the `memcpy` for copying over attacker controlled data in a fixed-size stack buffer is executed in a loop, and the check whether too many bytes were copied is executed *after* corruption in the next loop iteration. This check, once failed, also throws an exception, allowing for mounting a CHOP attack.

## Running the exploit

Unfortunately, we cannot provide an easy replicable setup for this case study, as we used two physical machines during exploit development:
Machine A, a macbook, with macOS Sierra v10.12 virtual machine and machine B with Ubuntu 20.04.4.

We realized a smartcard interface via TCP using [`virtualsmartcard`](https://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html).
Machine A virtual machine runs the vulnerable version of `CAC/smartcardservices` and machine B would fire the exploit via [`solve.py`](solve.py) using a modified version of [`virt_cacard`](https://github.com/PL4typus/virt_cacard) (commit [`f63058`](https://github.com/PL4typus/virt_cacard/tree/f6305832dcc43667c7c1e8a2b63c9c291259b03e), see the included [diff](virt_cacard.diff)).