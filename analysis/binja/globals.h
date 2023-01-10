string WHITE_LIST[11] = {"std::operator+<char, std::char_traits<char>, std::allocator<char> >(char const*, std::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)",
                        "std::operator+<char, std::char_traits<char>, std::allocator<char> >(char const*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)",
                        "std::operator+<char, std::char_traits<char>, std::allocator<char> >(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&&, char const*)",
                        "std::operator+<char, std::char_traits<char>, std::allocator<char> >(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, char const*)",
                        "std::operator+<char, std::char_traits<char>, std::allocator<char> >(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)",
                        "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::operator=(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&&)",
                        "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_append(char const*, uint64_t)",
                        "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_assign(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)",
                        "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_construct<char*>(char*, char*, std::forward_iterator_tag)",
                        "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_construct<char const*>(char const*, char const*, std::forward_iterator_tag)",
                        "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_create(uint64_t&, uint64_t)"
                        
} ;


string NO_TAINT_LIST[5] = {"__printf_chk", "__fprintf_chk", "getenv", "fgets", "gets" } ;

string LEAK_LIST[11] = {"__printf_chk", "__fprintf_chk", "gds__log", "g_log", "std::__ostream_insert<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*, int64_t)","std::__ostream_insert<wchar_t, std::char_traits<wchar_t> >(std::basic_ostream<wchar_t, std::char_traits<wchar_t> >&, wchar_t const*, int64_t", "std::ostream::operator<<(int32_t)", "std::operator<<<std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)", "std::operator<<<wchar_t, std::char_traits<wchar_t> >(std::basic_ostream<wchar_t, std::char_traits<wchar_t> >&, char const*)", "std::ostream::_M_insert<void const*>(void const*)", "jack_error"} ;

string NO_RETURNS[1] = {"std::terminate()"};


vector<string> THROW_VARIANTS = {"std::rethrow", "__cxa_rethrow", "std::__throw", "__cxa_throw_"};
string cxa_throw = {"__cxa_throw"};
vector<pair<string, string>> UNWIND_VARIANTS = { {"_Unwind_Resume_or_Rethrow", "RESUME_OR_RETHROW"} , 
                                        {"_Unwind_RaiseException" , "RAISE_EXCEPTION"}
};


vector<string> UAF = { "operator delete(void*)" , "operator delete[](void*)", "operator delete(void*, std::nothrow_t const&)", "operator delete(void*, uint64_t)", "operator delete[](void*, uint64_t)", "rtl_freeMemory", "free" };

vector<string> OSS_THROW_VARIANTS = {"std::rethrow", "__cxa_rethrow", "std::__throw", "__cxa_throw_", "_Unwind_Resume_or_Rethrow", "_Unwind_RaiseException"};


