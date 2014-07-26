(function(exports) {
	var shouldLoadConsts = true;
	var shouldLoadCFuncs = true;
	var shouldLoadFuncs = true;
	var funcsToLoad = ["exec", "include", "sizeof", "logify", "apply", "str2voidPtr", "voidPtr2str", "isMemoryReadable", "isObject"];
	
	// eval can't handle @encode etc.
	exports.exec = function(str) {		
		var mkdir = @encode(int (const char *, int))(dlsym(RTLD_DEFAULT, "mkdir"));
		var tempnam = @encode(char *(const char *, const char *))(dlsym(RTLD_DEFAULT, "tempnam"));
		var fopen = @encode(void *(const char *, const char *))(dlsym(RTLD_DEFAULT, "fopen"));
		var fclose = @encode(int (void *))(dlsym(RTLD_DEFAULT, "fclose"));
		var fwrite = @encode(int (const char *, int, int, void *))(dlsym(RTLD_DEFAULT, "fwrite"));
		var symlink = @encode(int (const char *, const char *))(dlsym(RTLD_DEFAULT, "symlink"));
		var unlink = @encode(int (const char *))(dlsym(RTLD_DEFAULT, "unlink"));
		var getenv = @encode(const char *(const char *))(dlsym(RTLD_DEFAULT, "getenv"));
		var setenv = @encode(int (const char *, const char *, int))(dlsym(RTLD_DEFAULT, "setenv"));
		
		var libdir = "/usr/lib/cycript0.9";
		var dir = libdir + "/tmp";

		mkdir(dir, 0777);
		
		// This is needed because tempnam seems to ignore the first argument on i386
		var old_tmpdir = getenv("TMPDIR");
		setenv("TMPDIR", dir, 1);

		// No freeing :(
		var f = tempnam(dir, "exec-");
		setenv("TMPDIR", old_tmpdir, 1);
		if(!f) {
			return false;
		}

		symlink(f, f + ".cy");
		
		str = "exports.result = " + str;

		var handle = fopen(f, "w");
		fwrite(str, str.length, 1, handle);
		fclose(handle);
		
		var r;
		var except = null;
		try {
			r = require(f.replace(libdir + "/", ""));
		} catch(e) {
			except = e;
		}

		unlink(f + ".cy");
		unlink(f);
		
		if(except !== null) {
			throw except;
		}

		return r.result;
	};
	exports.applyTypedefs = function(str) {
		var typedefs = {
			"restrict": "",
			"FILE": "void",
			"size_t": "uint64_t",
			"uintptr_t": "unsigned long",
			"kern_return_t": "int",
			"mach_port_t": "unsigned int",
			"mach_port_name_t": "unsigned int",
			"vm_offset_t": "unsigned long",
			"vm_size_t": "unsigned long",
			"mach_vm_address_t": "uint64_t",
			"mach_vm_offset_t": "uint64_t",
			"mach_vm_size_t": "uint64_t",
			"vm_map_offset_t": "uint64_t",
			"vm_map_address_t": "uint64_t",
			"vm_map_size_t": "uint64_t",
			"mach_port_context_t": "uint64_t",
			"vm_map_t": "unsigned int",
			"boolean_t": "unsigned int",
			"vm_prot_t": "int",
			"mach_msg_type_number_t": "unsigned int",
		};
		
		for(var k in typedefs) {
			str = str.replace(new RegExp("(\\s|\\*|,|\\(|^)" + k + "(\\s|\\*|,|\\)|$)", "g"), "$1" + typedefs[k] + "$2");
		}
		
		return str;
	};
	exports.include = function(str, load) {
		str = exports.applyTypedefs(str);
		
		var re = /^\s*([^(]*(?:\s+|\*))(\w*)\s*\(([^)]*)\)\s*;?\s*$/;
		var match = re.exec(str);
		if(!match) {
			return -1;
		}
		var rType = match[1];
		var name = match[2];
		var args = match[3];

		var argsRe = /([^,]+)(?:,|$)/g;
		var argsTypes = [];
		while((match = argsRe.exec(args)) !== null) {
			var type = match[1];
			argsTypes.push(type);
		}
		
		var encodeString = "@encode(";
		encodeString += rType + "(";
		encodeString += argsTypes.join(", ") + "))";

		var fun = dlsym(RTLD_DEFAULT, name);
		if(fun !== null) {
			encodeString += "(" + fun + ")";
			if(load) {
				return [name, exports.exec(encodeString)];
			}
		} else if(load) {
			throw "Function couldn't be found with dlsym!";
		}

		return [name, encodeString];
	};
	exports.constants = {
		VM_PROT_NONE:       0x0,
		VM_PROT_READ:       0x1,
		VM_PROT_WRITE:      0x2,
		VM_PROT_EXECUTE:    0x4,
		VM_PROT_NO_CHANGE:  0x8,
		VM_PROT_COPY:       0x10,
		VM_PROT_WANTS_COPY: 0x10,
		VM_PROT_IS_MASK:    0x40,
	};
	var c = exports.constants;
	c.VM_PROT_DEFAULT = c.VM_PROT_READ | c.VM_PROT_WRITE;
	c.VM_PROT_ALL =     c.VM_PROT_READ | c.VM_PROT_WRITE | c.VM_PROT_EXECUTE;
	
	if(shouldLoadConsts) {
		for(var k in c) {
			Cycript.all[k] = c[k];
		}
	}
	
	exports.funcs = {};
	exports.loadfuncs = function() {
		var defs = [
			// <stdlib.h>
			"void *calloc(size_t num, size_t size)",
			// <string.h>
			"char *strcpy(char *restrict dst, const char *restrict src)",
			"char *strdup(const char *s1)",
			// <stdio.h>
			"FILE *fopen(const char *, const char *)",
			"int fclose(FILE *)",
			"size_t fread(void *restrict, size_t, size_t, FILE *restrict)",
			"size_t fwrite(const void *restrict, size_t, size_t, FILE *restrict)",
			// <mach.h>
			"mach_port_t mach_task_self()",
			"kern_return_t task_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *tn)",
			"kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)",
			"kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt)",
			"kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt)",
		];

		for(var i = 0; i < defs.length; i++) {
			try {
				var o = exports.include(defs[i], true);
				exports.funcs[o[0]] = o[1];
				Cycript.all[o[0]] = o[1];
			} catch(e) {
				system.print("Failed to load function: " + i);
				try {
					system.print(exports.include(defs[i]));
				} catch(e2) {
					
				}
			}
		}
	};
	
	if(shouldLoadCFuncs) {
		exports.loadfuncs();
	}

	exports.sizeof = function(type) {
		if(typeof type === "string") {
			type = exports.applyTypedefs(type);
			type = exports.exec("@encode(" + type + ")");
		}
		
		// (const) char * has "infinite" preceision
		if(type.toString().slice(-1) === "*") {
			return exports.sizeof(@encode(void *));
		}

		if(type.toString() === @encode(float).toString()) {
			return 4;
		} else if (type.toString() === @encode(double).toString()) {
			return 8;
		}

		var typeInstance = type(0);
		
		if(typeInstance instanceof Object && "length" in typeInstance) {
			return typeInstance.length * exports.sizeof(typeInstance.type);
		}
		
		for(var i = 0; i < 5; i++) {
			var maxSigned = Math.pow(2, 8 * Math.pow(2, i) - 1) - 1;
			if(i === 3) {
				// Floating point fix ;^)
				maxSigned /= 1000;
			}

			// can't use !== or sizeof(void *) === 0.5
			if(type(maxSigned) != maxSigned) {
				return Math.pow(2, i - 1);
			}
		}
	};
	
	exports.logify = function(cls, sel) {
		@import com.saurik.substrate.MS;
		@import org.cycript.NSLog;
		
		var oldm = {};
		
		MS.hookMessage(cls, sel, function() {
			var args = [].slice.call(arguments);
			
			var selFormat = sel.toString().replace(/:/g, ":%@ ").trim();
			var logFormat = "%@[<%@: 0x%@> " + selFormat + "]";
			
			var standardArgs = [logFormat, class_isMetaClass(cls)? "+": "-", cls.toString(), (&this).valueOf().toString(16)];
			var logArgs = standardArgs.concat(args);
			
			NSLog.apply(null, logArgs);
			
			var r = oldm->apply(this, arguments);
			
			if(r !== undefined) {
				NSLog(" = %@", r);
			}
			
			return r;
		}, oldm);
		
		return oldm;
	};

	exports.apply = function(fun, args) {
		if(!(args instanceof Array)) {
			throw "Args needs to be an array!";
		}
		
		var argc = args.length;
		var voidPtr = new Type("v").pointerTo();
		var argTypes = [];
		for(var i = 0; i < argc; i++) {
			argTypes.push(voidPtr);
			
			if(typeof args[i] === "string") {
				args[i] = exports.str2voidPtr(args[i]);
			}
		}

		var type = voidPtr.functionWith.apply(voidPtr, argTypes);
		
		if(typeof fun === "string") {
			fun = dlsym(RTLD_DEFAULT, fun);
		}
		
		if(!fun) {
			throw "Function not found!";
		}

		return type(fun).apply(null, args);
	};
	
	exports.str2voidPtr = function(str) {
		var strdup = @encode(void *(char *))(dlsym(RTLD_DEFAULT, "strdup"));
		return strdup(str);
	};

	exports.voidPtr2str = function(voidPtr) {
		var strdup = @encode(char *(void *))(dlsym(RTLD_DEFAULT, "strdup"));
		return strdup(voidPtr);
	};
	
	exports.isMemoryReadable = function(ptr) {
		if(typeof ptr === "string") {
			return true;
		}
		
		var fds = new @encode(int [2]);
		exports.apply("pipe", [fds]);
		var result = exports.apply("write", [fds[1], ptr, 1]) == 1;
		
		exports.apply("close", [fds[0]]);
		exports.apply("close", [fds[1]]);
		
		return result;
	};
	
	exports.isObject = function(obj) {
		obj = @encode(void *)(obj);
		var lastObj = -1;
		
		function objc_isa_ptr(obj) {
			// See http://www.sealiesoftware.com/blog/archive/2013/09/24/objc_explain_Non-pointer_isa.html
			var objc_debug_isa_class_mask = 0x00000001fffffffa;
			obj = (obj & 1)? (obj & objc_debug_isa_class_mask): obj;
			
			if((obj & (exports.sizeof(@encode(void *)) - 1)) != 0) {
				return null;
			} else {
				return obj;
			}
		}
		
		function ptrValue(obj) {
			return obj? obj.valueOf(): null;
		}
		
		var foundMetaClass = false;
		
		for(obj = objc_isa_ptr(obj); exports.isMemoryReadable(obj); ) {
			obj = *@encode(void **)(obj);
			
			if(ptrValue(obj) == ptrValue(lastObj)) {
				foundMetaClass = true;
				break;
			}
			
			lastObj = obj;
		}
		
		if(!foundMetaClass) {
			return false;
		}
		
		if(lastObj === -1 || lastObj === null) {
			return false;
		}
		
		var obj_class = objc_isa_ptr(@encode(void **)(obj)[1]);
		
		if(!exports.isMemoryReadable(obj_class)) {
			return false;
		}
		
		var metaclass = objc_isa_ptr(@encode(void **)(obj_class)[0]);
		var superclass = objc_isa_ptr(@encode(void **)(obj_class)[1]);
		
		return ptrValue(obj) == ptrValue(metaclass) && superclass == null;
	};
	
	if(shouldLoadFuncs) {
		for(var i = 0; i < funcsToLoad.length; i++) {
			var name = funcsToLoad[i];
			Cycript.all[name] = exports[name];
		}
	}

})(exports);
