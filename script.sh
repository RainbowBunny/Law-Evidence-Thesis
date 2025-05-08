#!/bin/bash

for i in $(seq -w 0 9); do
    python3 PPChain.py > "openPIA/data${i}.txt"
done

