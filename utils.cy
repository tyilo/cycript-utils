(function(utils) {
	// Load C functions declared in CFuncsDeclarations
	var shouldLoadCFuncs = true;
	// Expose the C functions to cycript's global scope
	var shouldExposeCFuncs = true;
	// Expose C constants to cycript's global scope
	var shouldExposeConsts = true;
	// Expose functions defined here (in utils) to cycript's global scope
	var shouldExposeFuncs = true;

	utils.funcs = {};

	// Various constants
	utils.constants = {
		// <sys/mman.h>
		PROT_NONE:  0x0,
		PROT_READ:  0x1,
		PROT_WRITE: 0x2,
		PROT_EXEC:  0x4,
		// <sys/sysctl.h>
		CTL_MAXNAME: 12,
		// <mach/vm_prot.h>
		VM_PROT_NONE:       0x0,
		VM_PROT_READ:       0x1,
		VM_PROT_WRITE:      0x2,
		VM_PROT_EXECUTE:    0x4,
		VM_PROT_NO_CHANGE:  0x8,
		VM_PROT_COPY:       0x10,
		VM_PROT_WANTS_COPY: 0x10,
		VM_PROT_IS_MASK:    0x40,
		// <mach-o/loader.h>
		MH_MAGIC:    0xfeedface,
		MH_CIGAM:    0xcefaedfe,
		MH_MAGIC_64: 0xfeedfacf,
		MH_CIGAM_64: 0xcffaedfe,
		// <mach/machine.h>
		CPU_ARCH_ABI64: 0x01000000,
		CPU_TYPE_X86: 7,
		CPU_TYPE_ARM: 12,
	};

	var c = utils.constants;
	c.VM_PROT_DEFAULT = c.VM_PROT_READ | c.VM_PROT_WRITE;
	c.VM_PROT_ALL =     c.VM_PROT_READ | c.VM_PROT_WRITE | c.VM_PROT_EXECUTE;

	c.CPU_TYPE_X86_64 = c.CPU_TYPE_X86 | c.CPU_ARCH_ABI64;
	c.CPU_TYPE_ARM64 = c.CPU_TYPE_ARM | c.CPU_ARCH_ABI64;

	c.NSUTF8StringEncoding = 4;

	// Typedefs (always exposed)
	// <stdlib.h>
	typedef unsigned long size_t;

	// <stdio.h>
	typedef void FILE;

	// <stdint.h>
	typedef unsigned long uintptr_t;
	typedef long intptr_t;

	// <mach/mach.h>
	typedef int kern_return_t;
	typedef int natural_t;
	typedef int integer_t;

	typedef natural_t mach_port_name_t;
	typedef mach_port_name_t mach_port_t;

	typedef natural_t vm_offset_t;
	typedef natural_t vm_size_t;

	typedef uint64_t mach_vm_address_t;
	typedef uint64_t mach_vm_offset_t;
	typedef uint64_t mach_vm_size_t;

	typedef uint64_t vm_map_offset_t;
	typedef uint64_t vm_map_address_t;
	typedef uint64_t vm_map_size_t;

	typedef mach_vm_address_t mach_port_context_t;

	typedef mach_port_t vm_map_t;
	typedef int vm_prot_t;
	typedef natural_t mach_msg_type_number_t;

	typedef integer_t cpu_type_t;
	typedef integer_t cpu_subtype_t;
	typedef integer_t cpu_threadtype_t;

	if(@encode(void *).size == 8) {
		typedef unsigned int boolean_t;
	} else {
		typedef int boolean_t;
	}

	// Structs to be made with utils.makeStruct
	// Always exposed
	var structs = [
		["mach_header", "uint32_t magic; cpu_type_t cputype; cpu_subtype_t cpusubtype; uint32_t filetype; uint32_t ncmds; uint32_t sizeofcmds; uint32_t flags;"],
		["dyld_image_info", "const struct mach_header* imageLoadAddress; const char* imageFilePath; uintptr_t imageFileModDate;"],
		["dyld_all_image_infos", "uint32_t version; uint32_t infoArrayCount; const struct dyld_image_info* infoArray;"],
		["Dl_info", "const char *dli_fname; void *dli_fbase; const char *dli_sname; void *dlisaddr;"],
	];

	// C functions that utils.loadfuncs loads
	var CFuncsDeclarations = [
		// <stdlib.h>
		"void *calloc(size_t num, size_t size)",
		// <string.h>
		"char *strcpy(char *restrict dst, const char *restrict src)",
		"char *strdup(const char *s1)",
		"void *memset(void *dest, int ch, size_t count)",
		"void *memcpy(void *dest, const void *src, size_t count)",
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
		// <dlfcn.h>
		"int dladdr(const void* addr, Dl_info* info);",
	];

	var log = system.print;

	try {
		@import org.cycript.NSLog;
		log = x => NSLog("%@", x);
	} catch(e) {
	}

	/*
		Aligns the pointer downwards, aligment must be a power of 2
		Useful for mprotect

		Example:
			cy# utils.align(0x100044, 0x1000).toString(16)
			"100000"
	*/
	utils.align = function(ptr, alignment) {
		var high = Math.floor(ptr / Math.pow(2, 32));
		var low = ptr | 0;

		low = (low & ~(alignment - 1));

		if(low < 0) {
			low = Math.pow(2, 32) + low;
		}

		return low + high * Math.pow(2, 32);
	};

	/*
		Sets the protection of the memory starting at addr
		with length len, to prot

		Example:
			cy# var foo = new int;
			&0
			cy# utils.mprotect(foo.valueOf(),
			                   foo.type.size,
							   utils.constants.PROT_READ)
			cy# *a = 1
			*** _assert(CYRecvAll(client, &size, sizeof(size))):../Console.cpp(142):Run
	*/
	utils.mprotect = function(addr, len, prot) {
		addr = utils.getPointer(addr);

		var pagesize = utils.apply("getpagesize", []);

		var aligned = utils.align(addr, pagesize);

		var mprotect_size = addr - aligned + len;

		if(utils.apply("mprotect", [aligned, mprotect_size, prot])) {
			throw "mprotect failed.";
		}
	};

	/*
		Returns an array of all values associated with an object

		Example:
			cy# utils.getValues({a: 1, b: 2, c: 2})
			[1,2,2]
	*/
	utils.getValues = function(obj) {
		return Object.keys(obj).map(o => obj[o]);
	};

	var libdir = "/usr/lib/cycript0.9";

	function getTmpDir() {
		var dir = libdir + "/tmp";

		utils.apply("mkdir", [dir, 0777]);

		return dir;
	}

	function requireFile(path) {
		return require(path.replace(libdir + "/", "").replace(/.cy$/, ""));
	}

	/*
		Reloads this file into cycript for development purposes

		Example:
			cy# new_utils = utils.reloadUtils(); 0
			0
			cy# new_utils == utils
			false
	*/
	utils.reloadUtils = function() {
		var tmpdir = getTmpDir();

		var template = utils.str2voidPtr(tmpdir + "/XXXXXXXX");
		utils.apply("mkdtemp", [template]);

		var f = utils.voidPtr2str(template) + "/utils.cy";
		utils.apply("symlink", [libdir + "/com/tyilo/utils.cy", f]);

		var new_utils = requireFile(f);

		utils.apply("unlink", [f]);
		utils.apply("rmdir", [template]);

		return new_utils;
	};

	/*
		Runs an external program with arguments
		Returns the program's stdout

		Example:
			cy# utils.getOutputFromTask("/bin/date", ["+%s"])
			@"1419918861\n"
	*/
	utils.getOutputFromTask = function(path, args) {
		var task = [new NSTask init];
		task.launchPath = path;
		task.arguments = args;

		var pipe = [NSPipe pipe];
		task.standardOutput = pipe;

		[task launch];
		[task waitUntilExit];

		var data = [[pipe fileHandleForReading] readDataToEndOfFile];
		return [new NSString initWithData:data encoding:c.NSUTF8StringEncoding];
	};

	/*
		Replacement for eval that can handle @encode etc.

		Example:
			cy# utils.exec("@encode(void *(int, char))")
			@encode(void*(int,char))
	*/
	utils.exec = function(expression) {
		var dir = getTmpDir();

		var template = utils.str2voidPtr(dir + "/exec-XXXXXXXX.cy");

		utils.apply("mkstemps", [template, 3]);
		var f = utils.voidPtr2str(template);
		free(template);

		if(!f) {
			return false;
		}

		var str = "exports.result = " + expression;

		var handle = utils.apply("fopen", [f, "w"]);
		if(!handle) {
			throw "utils.exec: Couldn't write to temporary file. Is the process sandboxed?";
		}
		utils.apply("fwrite", [str, str.length, 1, handle]);
		utils.apply("fclose", [handle]);

		var r;
		var except = null;
		try {
			r = requireFile(f);
		} catch(e) {
			except = e;
		}

		utils.apply("unlink", [f]);

		if(except !== null) {
			throw except;
		}

		return r.result;
	};

	/*
		Fixes types for use with @encode
		Replaces "struct" and "restrict" by nothing, as Cycript doesn't support these
		Used in utils.include, utils. and utils.makeStruct

		Example:
			cy# utils.fixType("struct mach_header")
			"mach_header"
			cy# utils.fixType("void *restrict")
			"void *"
	*/
	utils.fixType = function(str) {
		return str.replace(/struct|restrict/g, "");
	};

	/*
		Parses a C function declaration and returns the function name and cycript type
		If load is true, tries to load it into cycript using utils.exec

		Example:
			cy# var str = "void *calloc(size_t num, size_t size)";
			"void *calloc(size_t num, size_t size)"
			cy# utils.include(str)
			["calloc","@encode(void *(uint64_t num,  uint64_t size))(140735674376857)"]
			cy# var ret = utils.include(str, true)
			["calloc",0x7fff93e0e299]
			cy# ret[1].type
			@encode(void*(unsigned long long int,unsigned long long int))
			cy# ret[1](100, 1)
			0x100444100
	*/
	utils.include = function(str, load) {
		var re = /^\s*([^(]*(?:\s+|\*))(\w*)\s*\(([^)]*)\)\s*;?\s*$/;
		var match = re.exec(str);
		if(!match) {
			return -1;
		}
		var rType = utils.fixType(match[1]);
		var name = match[2];
		var args = match[3];

		var argsRe = /([^,]+)(?:,|$)/g;
		var argsTypes = [];
		while((match = argsRe.exec(args)) !== null) {
			var type = utils.fixType(match[1]);
			argsTypes.push(type);
		}

		var encodeString = "@encode(";
		encodeString += rType + "(";
		encodeString += argsTypes.join(", ") + "))";

		var fun = dlsym(RTLD_DEFAULT, name);
		if(fun !== null) {
			encodeString += "(" + fun + ")";
			if(load) {
				return [name, utils.exec(encodeString)];
			}
		} else if(load) {
			throw "utils.include: Function couldn't be found with dlsym!";
		}

		return [name, encodeString];
	};

	/*
		Loads the function declaration in the defs array using utils.exec and exposes to cycript's global scope
		Is automatically called if shouldLoadCFuncs is true
	*/
	utils.loadfuncs = function(expose) {
		for(var f of CFuncsDeclarations) {
			try {
				var o = utils.include(f, true);
				utils.funcs[o[0]] = o[1];
				if(expose) {
					Cycript.all[o[0]] = o[1];
				}
			} catch(e) {
				log("Failed to load function: ");
				log(f);
				try {
					log(utils.include(f));
				} catch(e2) {

				}
			}
		}
	};

	utils.hex = function(ptr) {
		return '0x' + utils.getPointer(ptr).toString(16);
	};

	/*
		Logs a specific message sent to an instance of a class like logify.pl in theos
		Requires Cydia Substrate (com.saurik.substrate.MS) and NSLog (org.cycript.NSLog) modules
		Returns the old message returned by MS.hookMessage (Note: this is not just the old message!)

		FIXME: For certain combinations of arguments, the process will crash

		Example:
			cy# var oldm = utils.logify(objc_getMetaClass(NSNumber), @selector(numberWithDouble:))
			...
			cy# var n = [NSNumber numberWithDouble:1.5]
			2014-07-28 02:26:39.805 cycript[71213:507] +[<NSNumber: 0x10032d0c4> numberWithDouble:1.5]
			2014-07-28 02:26:39.806 cycript[71213:507]  = 1.5
			@1.5
	*/
	utils.logify = function(cls, sel) {
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

	/*
		Similar to utils.logify, but for functions instead of messages

		Example:
			cy# logifyFunc("fopen", 2);
			...
			cy# apply("fopen", ["/etc/passwd", "r"]);
			2015-01-14 07:01:08.009 cycript[55326:2042054] fopen(0x10040d4cc, 0x10040d55c)
			2015-01-14 07:01:08.010 cycript[55326:2042054]  = 0x7fff754fc070
			0x7fff754fc070
	*/

	utils.logifyFunc = function(nameOrPointer, argCount) {
		@import com.saurik.substrate.MS;
		@import org.cycript.NSLog;

		var name = "" + nameOrPointer;

		var ptr = nameOrPointer;
		if(typeof nameOrPointer === "string") {
			ptr = dlsym(RTLD_DEFAULT, nameOrPointer);
			if(!ptr) {
				throw "Couldn't find function with name using dlsym!";
			}
		}

		var oldf = {};
		var f = function() {
			var logFormat = "%@(";
			for(var i = 0; i < arguments.length; i++) {
				logFormat += (i > 0? ", ": "") + "%@";
			}
			logFormat += ")";

			var args = [].slice.call(arguments);

			args = args.map(utils.hex);

			NSLog.apply(null, [logFormat, name].concat(args));

			var r = (*oldf).apply(null, arguments);

			if(r !== undefined) {
				NSLog(" = %@", utils.hex(r));
			}

			return r;
		};

		var voidPtr = @encode(void *);
		var argTypes = [];

		for(var i = 0; i < argCount; i++) {
			argTypes.push(voidPtr);
		}

		var fType = voidPtr.functionWith.apply(voidPtr, argTypes);

		MS.hookFunction(fType(ptr), fType(f), oldf);

		return oldf;
	};

	/*
		Calls a C function by providing its name and arguments
		Doesn't support structs
		Return value is always a void pointer

		Example:
			cy# utils.apply("printf", ["%s %.3s, %d -> %c, float: %f\n", "foo", "barrrr", 97, 97, 1.5])
			foo bar, 97 -> a, float: 1.500000
			0x22
	*/
	utils.apply = function(fun, args) {
		if(!(args instanceof Array)) {
			throw "utils.apply: Args needs to be an array!";
		}

		var argc = args.length;
		var voidPtr = @encode(void *);
		var argTypes = [];
		for(var i = 0; i < argc; i++) {
			var argType = voidPtr;

			var arg = args[i];
			if(typeof arg === "string") {
				argType = @encode(char *);
			}
			if(typeof arg === "number" && arg % 1 !== 0) {
				argType = @encode(double);
			}

			argTypes.push(argType);
		}

		var type = voidPtr.functionWith.apply(voidPtr, argTypes);

		if(typeof fun === "string") {
			fun = dlsym(RTLD_DEFAULT, fun);
		}

		if(!fun) {
			throw "utils.apply: Function not found!";
		}

		return type(fun).apply(null, args);
	};

	/*
		Converts a string (char *) to a void pointer (void *)
		You can't cast to strings to void pointers and vice versa in cycript. Blame saurik.

		Example:
			cy# var voidPtr = utils.str2voidPtr("foobar")
			0x100331590
			cy# utils.voidPtr2str(voidPtr)
			"foobar"
	*/
	utils.str2voidPtr = function(str) {
		var strdup = @encode(void *(char *))(dlsym(RTLD_DEFAULT, "strdup"));
		return strdup(str);
	};

	/*
		The inverse function of str2voidPtr
	*/
	utils.voidPtr2str = function(voidPtr) {
		var strdup = @encode(char *(void *))(dlsym(RTLD_DEFAULT, "strdup"));
		return strdup(voidPtr);
	};

	/*
		Converts a double into a void pointer
		This can be used to view the binary representation of a floating point number

		Example:
			cy# var n = utils.double2voidPtr(-1.5)
			0xbff8000000000000
			cy# utils.voidPtr2double(n)
			-1.5
	*/
	utils.double2voidPtr = function(n) {
		var doublePtr = new double;
		*doublePtr = n;

		var voidPtrPtr = @encode(void **)(doublePtr);

		return *voidPtrPtr;
	};

	/*
		The inverse function of double2voidPtr
	*/
	utils.voidPtr2double = function(voidPtr) {
		var voidPtrPtr = new @encode(void **);
		*voidPtrPtr = voidPtr;

		var doublePtr = @encode(double *)(voidPtrPtr);

		return *doublePtr;
	};

	/*
		Determines in a safe way if a memory location is readable

		Example:
			cy# utils.isMemoryReadable(0)
			false
			cy# utils.isMemoryReadable(0x1337)
			false
			cy# utils.isMemoryReadable(NSObject)
			true
			cy# var a = malloc(100); utils.isMemoryReadable(a)
			true
	*/
	utils.isMemoryReadable = function(ptr) {
		if(typeof ptr === "string") {
			return true;
		}

		var fds = new @encode(int [2]);
		utils.apply("pipe", [fds]);
		var result = utils.apply("write", [fds[1], ptr, 1]) == 1;

		utils.apply("close", [fds[0]]);
		utils.apply("close", [fds[1]]);

		return result;
	};

	/*
		Returns the pointer to an object as a number
		Returns null if the input isn't a number or doesn't represent a memory location

		Example:
			cy# utils.getPointer(0)
			0
			cy# utils.getPointer(1234)
			1234
			cy# utils.getPointer(NSObject)
			140735254495472
			cy# utils.getPointer([])
			null
	*/
	utils.getPointer = function(obj) {
		if(obj === 0 || obj === null) {
			return 0;
		}

		var p = @encode(void *)(obj);

		if(p === null) {
			return null;
		}

		return p.valueOf();
	};

	/*
		Determines if two object has the same pointer value

		Example:
			cy# var ptr = utils.getPointer(NSObject)
			140735254495472
			cy# utils.pointerCompare(ptr, NSObject)
			true
			cy# utils.pointerCompare(ptr, NSString)
			false
	*/

	utils.pointerCompare = function(o1, o2) {
		if(o1 === o2) {
			return true;
		}

		return utils.getPointer(o1) === utils.getPointer(o2);
	};

	/*
		Determines in a safe way if the memory location is a registered Objective-C class or metaclass

		Example:
			cy# utils.isClass(0x1337)
			false
			cy# utils.isClass(NSObject)
			true
			cy# utils.isClass(object_getClass(NSObject))
			true

	*/
	utils.isClass = function(obj) {
		var ptr = utils.getPointer(obj);

		if(!ptr) {
			return false;
		}

		var classes = utils.getValues(ObjectiveC.classes);

		for(var i = 0; i < classes.length; i++) {
			var c = classes[i];
			if(utils.pointerCompare(ptr, c)) {
				return true;
			}

			var metaclass = object_getClass(c);

			if(utils.pointerCompare(ptr, metaclass)) {
				return true;
			}
		}

		return false;
	};

	/*
		Determines in a safe way if the memory location contains an Objective-C object

		Example:
			cy# utils.isObject(0x1337)
			false
			cy# utils.isObject(NSObject)
			true
			cy# utils.isObject(object_getClass(NSObject))
			true
			cy# utils.isObject([new NSObject init])
			true
			cy# var a = malloc(100); utils.isObject(a)
			false
			cy# *@encode(void **)(a) = NSObject; utils.isObject(a)
			true
	*/
	utils.isObject = function(obj) {
		function safe_objc_isa_ptr(ptr) {
			if(!utils.isMemoryReadable(ptr)) {
				return false;
			}

			var isa = utils.getPointer(*@encode(void **)(ptr));

			// See http://www.sealiesoftware.com/blog/archive/2013/09/24/objc_explain_Non-pointer_isa.html
			var objc_debug_isa_class_mask = 0x00000001fffffffa;
			isa = (isa & 1)? (isa & objc_debug_isa_class_mask): isa;

			if((isa & (@encode(void *).size - 1)) != 0) {
				return null;
			} else {
				return isa;
			}
		}

		var ptr = utils.getPointer(obj);

		if(!ptr) {
			return false;
		}

		if(utils.isClass(ptr)) {
			return true;
		}

		var c = safe_objc_isa_ptr(ptr);
		if(!utils.isClass(c)) {
			return false;
		}

		var msize = utils.apply("malloc_size", [ptr]);
		var isize = class_getInstanceSize(new Instance(c));

		return msize >= isize;
	};

	/*
		Creates a cycript struct type from a C struct definition

		Example:
			cy# var foo = makeStruct("int a; short b; char c; uint64_t d; double e;", "foo");
			@encode(foo)
			cy# var f = new foo
			&{a:0,b:0,c:0,d:0,e:0}
			cy# f->a = 100; f
			&{a:100,b:0,c:0,d:0,e:0}
			cy# *@encode(int *)(f)
			100
	*/
	utils.makeStruct = function(str, name) {
		var fieldRe = /(?:\s|\n)*([^;]+\s*(?:\s|\*))([^;]+)\s*;/g;

		var hasname = !!name;
		if(!hasname) {
			name = "_unnamed_struct" + Math.floor(Math.random() * 100000);
		}
		var typeStr = "{" + name + "=";

		while((match = fieldRe.exec(str)) !== null) {
			var fieldType = utils.fixType(match[1]);
			var fieldName = match[2];
			var encodedType = utils.exec("@encode(" + fieldType + ")").toString();

			typeStr += '"' + fieldName + '"' + encodedType;
		}

		typeStr += "}";

		var t = new Type(typeStr);
		if(hasname) {
			Cycript.all[name] = t;
		}
		return t;
	};

	/*
		Dumps all UI/NS Image instances to a temporary folder
		Optionally takes a filter function to filter which images to dump

		Example:
			cy# utils.dumpImages()
			"43 images written to /tmp/cycript-images-rdIbcB"
			cy# utils.dumpImages(img => img.size.width == 16)
			"5 images written to /tmp/cycript-images-8oso44"
	*/
	utils.dumpImages = function(filter_fun) {
		var image_class = ObjectiveC.classes["UIImage"] || ObjectiveC.classes["NSImage"];
		var images = choose(image_class);

		if(filter_fun) {
			images = images.filter(filter_fun);
		}

		if(images.length === 0) {
			throw "utils.dumpImages: No images found!"
		}

		var template = utils.str2voidPtr("/tmp/cycript-images-XXXXXX");
		utils.apply("mkdtemp", [template]);
		var dir = utils.voidPtr2str(template);

		for(var i of images) {
			data = [i TIFFRepresentation];
			[data writeToFile:dir + "/0x" + utils.getPointer(i).toString(16) + ".tiff" atomically:YES];
		}

		return images.length + " images written to " + dir;
	}

	var app_class = ObjectiveC.classes["UIApplication"] || ObjectiveC.classes["NSApplication"];
	var app = app_class && [app_class sharedApplication];

	/*
		Uses a heuristic method to determine if the object's class is an Apple provided one

		Example:
			cy# @implementation TestClass : NSObject {} @end
			#"TestClass"
			cy# utils.is_not_standard_class([new TestClass init])
			true
			cy# utils.is_not_standard_class([new NSObject init])
			false
	*/
	utils.is_not_standard_class = function(obj) {
		var classname = [obj className];
		while(classname[0] == "_") {
			classname = classname.substr(1);
		}
		return !([classname hasPrefix:"UI"] || [classname hasPrefix:"NS"]);
	};

	/*
		Internal function used utils.find_subviews and utils.find_subview_controllers
	*/
	function find_subviews_internal(view, predicate, transform) {
		var arr = [];
		var o = transform(view);
		if(o && predicate(o)) {
			arr.push(o);
		}

		return arr.concat.apply(arr, view.subviews.map(x => find_subviews_internal(x, predicate, transform)));
	}

	/*
		Recusirvely finds all subviews satisfying a predicate
		By default returns all subviews from the app's keyWindow

		Example:
			cy# utils.find_subviews().length
			421
			cy# utils.find_subviews(utils.is_not_standard_class).length
			48
			cy# utils.find_subviews(x => true, choose(UINavigationItemView)[0]).length
			2
	*/
	utils.find_subviews = function(predicate, view) {
		predicate = predicate || (x => true);
		view = view || app.keyWindow;

		return find_subviews_internal(view, predicate, x => x);
	};

	/*
		Like utils.find_subviews but for viewcontrollers instead of views
	*/
	utils.find_subview_controllers = function(predicate, view) {
		predicate = predicate || (x => true);
		view = view || app.keyWindow;

		return find_subviews_internal(view, predicate, x => x.viewDelegate || x.delegate);
	};

	/*
		Finds all classes with only one instance in the app's keyWindow's subviews
		Also filter outs classes which are provided by Apple

		Example:
			cy# utils.find_interesting_view_classes().length
			9
	*/
	utils.find_interesting_view_classes = function() {
		var views = utils.find_subviews();
		var classes = views.map(x => x.className.toString());

		var interesting_classes = classes.filter(x => classes.indexOf(x) === classes.lastIndexOf(x));

		return interesting_classes;
	};

	/*
		Like utils.find_interesting_view_classes but for viewcontroller classes
	*/
	utils.find_interesting_viewcontroller_classes = function() {
		var views = utils.find_subview_controllers();
		var classes = views.map(x => x.className.toString());

		var interesting_classes = classes.filter(x => classes.indexOf(x) === classes.lastIndexOf(x));

		return interesting_classes;
	};

	/*
		Recursively returns the superviews of the view

		Example:
			cy# utils.view_hierarchy(UIApp.keyWindow.subviews[0].subviews[0])
			[#"<UIWindow: ...>",#"<UILayoutContainerView: ...>",#"<UINavigationTransitionView: ...>"]
	*/
	utils.view_hierarchy = function(view) {
		var arr = [];
		do {
			arr.unshift(view);
		} while(view = view.superview);

		return arr;
	};

	/*
		Determines if an UI/NS View is on the screen

		Example:
			cy# utils.is_on_screen(UIApp.keyWindow)
			true
			cy# utils.is_on_screen([new UIView init])
			false
	*/
	utils.is_on_screen = function(view) {
		var hierarchy = utils.view_hierarchy(view);

		return !![hierarchy[0] isEqual:app.keyWindow];
	};

	/*
		Returns the common superview of the two views
		and two integers with the distance between the views and the superview

		Example:
			cy# rootview = [new UIView init]
			...
			cy# subview1 = [new UIView init]; [rootview addSubview:subview1];
			cy# subview2 = [new UIView init]; [rootview addSubview:subview2];
			cy# subview22 = [new UIView init]; [subview2 addSubview:subview22];
			cy# utils.view_relation(subview1, subview22)
			[#"<UIView: ...>",1,2]
			cy# utils.view_relation(subview1, subview2)
			[#"<UIView: ...>",1,1]
			cy# utils.view_relation(rootview, [new UIView init])
			null
	*/
	utils.view_relation = function(view1, view2) {
		var view_hierarchy1 = utils.view_hierarchy(view1);
		var view_hierarchy2 = utils.view_hierarchy(view2);

		var i;
		for(i = 0; [view_hierarchy1[i] isEqual:view_hierarchy2[i]]; i++) {
		}

		if(i === 0) {
			return null;
		}

		return [view_hierarchy1[i - 1], view_hierarchy1.length - i, view_hierarchy2.length - i];
	};

	/*
		Returns a pointer to type with a size of size * type.size

		Example:
			cy# var arr = utils.makeArray(int, 4)
			&0
			cy# arr[1] = 100
			100
	*/
	utils.makeArray = function(type, size) {
		var mem = malloc(size * type.size);
		return type.pointerTo()(mem);
	};

	/*
		Returns a pointer to type initialized with val

		Example:
			cy# var ptr = utils.pointerTo(int, 1337)
			&1337
			cy# *ptr
			1337
	*/
	utils.pointerTo = function(type, val) {
		var mem = new type;
		*mem = val;
		return mem;
	};

	/*
		Returns an array with two integers specifying
		the CPU_TYPE and CPU_SUB_TYPE of the current running process
		If the executable is fat, this returns the value for the active slice

		Example:
			cy# utils.getCpuType() // x86_64
			[16777223,0]
			cy# utils.getCpuType() // i368
			[7,0]
			cy# utils.getCpuType() // arm 32 bit
			[12,0]
	*/
	utils.getCpuType = function() {
		var mibLen = c.CTL_MAXNAME;
		var mib = utils.makeArray(int, mibLen);
		var mibLenPtr = utils.pointerTo(uint64_t, mibLen);
		var err = utils.apply("sysctlnametomib", ["sysctl.proc_cputype", mib, mibLenPtr]);

		if(err !== null) {
			free(mib);
			free(mibLenPtr);
			throw "utils.getCpuType: Error calling sysctlnametomib!";
		}

		mibLen = *mibLenPtr;
		free(mibLenPtr);
		mib[mibLen] = utils.apply("getpid", []);
		mibLen++;

		current_arch = utils.makeStruct("cpu_type_t type; cpu_subtype_t subtype;");
		archType = new current_arch;
		archTypeSizePtr = utils.pointerTo(uint64_t, current_arch.size);
		err = utils.apply("sysctl", [mib, mibLen, archType, archTypeSizePtr, 0, 0]);

		free(mib);
		free(archTypeSizePtr);
		if(err != null) {
			free(archType);
			throw "utils.getCpuType: Error calling sysctl!";
		}

		var ret = [archType->type, archType->subtype];
		free(archType);

		return ret;
	};

	/*
		Pads a hex number with zeros so it represents a certain number of bytes

		Example:
			cy# utils.hexpad(1, 4)
			"00000001"
			cy# utils.hexpad(0xffffff, 4)
			"00ffffff"
	*/
	utils.hexpad = function(num, bytes) {
		if(typeof num === "string") {
			num = Number(num);
		}

		var hex = num.toString(16);
		var padded = Array(bytes * 2 + 1).join('0') + hex;
		return padded.slice(-Math.max(2 * bytes, hex.length));
	};

	/*
		Returns a string containing the address and path to every loaded image in the process

		Example:
			cy# ?expand
			expand == true
			cy# utils.get_dyld_info()
			"
			0x0000000100000000: /Users/Tyilo/bin/nsrunlooper
			0x00007fff89ff4000: /usr/lib/libobjc.A.dylib
			0x00007fff9325f000: /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation
			0x00007fff9324f000: /usr/lib/libSystem.B.dylib
			0x00007fff8cec6000: /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
			..."
	*/
	utils.get_dyld_info = function() {
		var all_image_infos = dyld_all_image_infos.pointerTo()(utils.apply("_dyld_get_all_image_infos", []));
		var image_count = all_image_infos->infoArrayCount;
		var info_array = all_image_infos->infoArray;

		var log = "";

		for(var i = 0; i < image_count; i++) {
			var info = dyld_image_info.pointerTo()(&info_array[i]);

			var base = info->imageLoadAddress.valueOf();
			log += "\n0x" + utils.hexpad(base, @encode(void *).size) + ": " + info->imageFilePath;
		}

		return log;
	};

	/*
		Returns a string of hexpairs representing the memory
		starting at addr with length len

		Example:
			cy# var foo = new int;
			cy# *foo = 0x12345678
			305419896
			cy# utils.gethex(foo, foo.type.size)
			"78563412"
	*/
	utils.gethex = function(addr, len) {
		addr = utils.getPointer(addr);

		var res = "";

		var p = @encode(uint8_t *)(addr);

		for(var i = 0; i < len; i++) {
			res += utils.hexpad(p[i], 1);
		}

		return res;
	};

	/*
		Returns a hexdump of a memory range with similar format as xxd

		Example:
			cy# var foo = new int;
			cy# *foo = 0x12345678
			305419896
			cy# ?expand
			expand == true
			cy# utils.hexdump(foo, foo.type.size)
			"
			01005015a0:	78 56 34 12 	xV4.
			"
	*/
	utils.hexdump = function(addr, len, bytes_per_line) {
		addr = utils.getPointer(addr);

		if(!len) {
			len = 0x100;
		}

		if(!bytes_per_line) {
			bytes_per_line = 0x10;
		}

		function isprint(c) {
			return 0x20 <= c && c <= 0x7E;
		}

		var p = @encode(uint8_t *)(addr);
		var res = "\n";

		var addr_len = Math.ceil((addr + len - 1).toString(16).length / 2);

		for(var i = 0; i < len; i += bytes_per_line) {
			var cols = [utils.hexpad(addr + i, addr_len) + ":", "", ""];

			for(var j = i; j < i + bytes_per_line && j < len; j++) {
				var n = p[j];
				cols[1] += utils.hexpad(n, 1) + " ";
				cols[2] += isprint(n)? String.fromCharCode(n): ".";
			}

			res += cols.join("\t") + "\n";
		}

		return res;
	};

	function getRasm2Args(addr) {
		addr = utils.getPointer(addr);

		var cpuType = utils.getCpuType();

		var bits = "32";
		if(cpuType[0] & c.CPU_ARCH_ABI64) {
			bits = "64";
		}

		var arch;
		if(cpuType[0] & c.CPU_TYPE_X86) {
			arch = "x86";
		} else if(cpuType[0] & c.CPU_TYPE_ARM) {
			arch = "arm";
		} else {
			throw "Unknown arch for cpu: " + cpuType.join(", ");
		}

		var args = ["-a", arch, "-b", bits, "-o", addr.toString()];
		return args;
	}

	function getRasm2Output(args) {
		var rasm2_path = utils.getOutputFromTask("/bin/bash", ["-c", "which rasm2"]).trim();

		if(!rasm2_path) {
			throw "rasm2 command not found in /bin/bash's $PATH";
		}

		return utils.getOutputFromTask(rasm2_path, args);
	}

	/*
		Disassembles a memory range using rasm2

		Example:
			cy# ?expand
			expand == true
			cy# var method = class_getInstanceMethod(NSNumber,
			                 @selector(intValue));
			...
			cy# var imp = method_getImplementation(method);
			...
			cy# utils.disasm(imp, 10)
			"
			0x7fff83363b8c   1                       55  push rbp
			0x7fff83363b8d   3                   4889e5  mov rbp, rsp
			0x7fff83363b90   2                     4157  push r15
			0x7fff83363b92   2                     4156  push r14
			0x7fff83363b94   2                     4155  push r13
			"
	*/
	utils.disasm = function(addr, len) {
		addr = utils.getPointer(addr);

		if(!len) {
			len = 0x40;
		}

		var args = getRasm2Args(addr);

		var hex = utils.gethex(addr, len);
		args.push("-D", hex);

		return "\n" + getRasm2Output(args);
	};

	/*
		Assembles some instructions to a memory address using rasm2

		Example:
			cy# var n = [NSNumber numberWithInt:10]
			@10
			cy# [n intValue]
			10
			cy# var method = class_getInstanceMethod([n class],
			                 @selector(intValue));
			...
			cy# var imp = method_getImplementation(method);
			...
			cy# utils.asm(imp, 'mov eax, 42; ret;')
			6
			cy# [n intValue]
			42
	*/
	utils.asm = function(addr, ins) {
		addr = utils.getPointer(addr);

		var args = getRasm2Args(addr);

		args.push("--", ins);

		var output = getRasm2Output(args).trim();

		if(!output) {
			throw "Couldn't assemble instructions with rasm2.";
		}

		utils.mprotect(addr, output.length / 2, c.PROT_READ | c.PROT_WRITE | c.PROT_EXEC);

		var p = @encode(uint8_t *)(addr);

		for(var i = 0; i < output.length; i += 2) {
			p[i / 2] = parseInt(output[i] + output[i + 1], 16);
		}

		return output.length / 2;
	};

	if(shouldExposeConsts) {
		for(var k in utils.constants) {
			Cycript.all[k] = utils.constants[k];
		}
	}

	if(shouldExposeFuncs) {
		for(var k in utils) {
			if(utils.hasOwnProperty(k)) {
				var f = utils[k];
				if(typeof f === 'function') {
					Cycript.all[k] = f;
				}
			}
		}
	}

	try {
		for(var s of structs) {
			utils.makeStruct(s[1], s[0]);
		}
	} catch(e) {
		log(e);
		log("Failed to make structs!");
	}

	if(shouldLoadCFuncs) {
		utils.loadfuncs(shouldExposeCFuncs);
	}
})(exports);
