
-------
Concolic execution for Cortex-M has the following dependencies:

1. It depends on angr for symbolic execution (**Only use angr in this repo because offical angr has bugs?**).
2. It depends on **modified** QEMU for concrete execution.
3. It incorporates the (extended) avatar2 framework for state transfers (**Only use avatar2 in this repo**).

To install, `pip install -e ./`
