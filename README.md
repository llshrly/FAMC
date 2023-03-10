# FAMC: Fair and Public Auditable Multi-Party Computation with Cheater Detection

### Requirements packages
---
  * [`MPyC`](https://github.com/lschoe/mpyc)
  * [`SymPy`](https://github.com/sympy/sympy)

### Executing the Code

Multithreading simulates multi-party computation(take 3 parties for example):

	python FAMC.py -M 3
	
Multiple servers perform multi-party computation:
	
	rank0: python FAMC.py -P localhost -P {rank1 ip address} -P {rank2 ip address} -I0

	rank1: python FAMC.py -P {rank0 ip address} -P localhost -P {rank2 ip address} -I1

	rank2: python FAMC.py -P {rank0 ip address} -P {rank1 ip address} -P localhost -I2
