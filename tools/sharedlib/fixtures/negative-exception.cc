extern "C" int feature(int value) {
    if (value) throw value;
    return 0;
}
