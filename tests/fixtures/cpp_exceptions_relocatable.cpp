struct E1 {};
struct E2 {};

int may_throw(int x) {
    if (x == 1) throw E1();
    if (x == 2) throw E2();
    return x;
}

int caller(int x) {
    try {
        return may_throw(x);
    } catch (E1&) {
        return -1;
    } catch (E2&) {
        return -2;
    } catch (...) {
        return -3;
    }
}
