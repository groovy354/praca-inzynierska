#!/bin/bash 

cat $1 | sed -r "s/ ([iwzoau]) / \1\\\\ /g" > $2