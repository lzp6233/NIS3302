file(REMOVE_RECURSE
  "libdocopt.a"
  "libdocopt.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/docopt_s.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
