This folder contains the dataset we are using, ideally, you can use the `pickle` files directly. Each pickle file is a dictionary, mapping function name to its feature, `{function_name: features}`. Each feature is also a dictionary, and it contains the following attributes (by now):

```py
{
'name': function name,
'num_call_sites': the number of function calls,
'size_func': the size of the function,
'num_arguments': the number of arguments,
'constants': constants used in the function, stored as set,
'num_nodes': number of nodes in the CFG,
'num_edges': number of edges in the CFG,
'graph': the CFG of the function, it's a NetworkX graph,
}
```


In case you want to re-extract the features from the executables, do the following:

1. Make sure you have `gcc`, `clang` and `tcc` installed on your computer. 
2. Run `compile_all.sh` to extract the tarballs and compile the executables.
3. Run `mk_dataset.py` to extract features from the executables.

