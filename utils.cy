(function(utils) {
	// Load C functions declared in utils.loadFuncs
	var shouldLoadCFuncs = true;
	// Expose the C functions to cycript's global scope
	var shouldExposeCFuncs = true;
	// Expose C constants to cycript's global scope
	var shouldExposeConsts = true;
	// Expose functions defined here to cycript's global scope
	var shouldExposeFuncs = true;
	// Which functions to expose
	var funcsToExpose = ["align", "getKeys", "reloadUtils", "exec", "include", "sizeof", "logify", "apply", "str2voidPtr", "voidPtr2str", "double2voidPtr", "voidPtr2double", "isMemoryReadable", "isObject", "makeStruct", "dumpImages"];
	
	// C functions that utils.loadFuncs loads
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
	];
	
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

	/*
		Aligns the pointer downwards, aligment must be a power of 2
		Useful for mprotect

		Usage:
			cy# utils.align(0x100044, 0x1000).toString(16)
			"100000"
	*/
	utils.align = function(ptr, alignment) {
		var high = Math.floor(ptr / Math.pow(2, 32));
		var low = ptr | 0;
		
		low = (low & ~(alignment - 1));
		
		return low + high * Math.pow(2, 32);
	};
	
	/*
		Returns an array of all keys associated with an object
		Useful for inspecting the global Cycript object
		
		Usage:
			cy# utils.getKeys(Cycript)
			["gc","Functor","Pointer","Type","all","alls","ObjectiveC","Instance","Selector","objc_super"]
	*/
	utils.getKeys = function(obj) {
		var keys = [];
		for(k in obj) {
			keys.push(k);
		}
		return keys;
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
		
		Usage:
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
		Replacement for eval that can handle @encode etc.
		
		Usage:
			cy# utils.exec("@encode(void *(int, char))")
			@encode(void*(int,char))
	*/
	utils.exec = function(str) {
		var dir = getTmpDir();
		
		var template = utils.str2voidPtr(dir + "/exec-XXXXXXXX.cy");
		
		utils.apply("mkstemps", [template, 3]);
		var f = utils.voidPtr2str(template);
		free(template);
		
		if(!f) {
			return false;
		}
		
		str = "exports.result = " + str;

		var handle = utils.apply("fopen", [f, "w"]);
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
		Applies known typedefs
		Used in utils.include and utils.makeStruct
		
		Usage:
			cy# utils.applyTypedefs("mach_vm_address_t")
			"uint64_t"
	*/
	utils.applyTypedefs = function(str) {
		var typedefs = {
			"struct": "",
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
			"cpu_type_t": "int",
			"cpu_subtype_t": "int",
			"cpu_threadtype_t": "int",
		};
		
		for(var k in typedefs) {
			str = str.replace(new RegExp("(\\s|\\*|,|\\(|^)" + k + "(\\s|\\*|,|\\)|$)", "g"), "$1" + typedefs[k] + "$2");
		}
		
		return str;
	};
	
	/*
		Parses a C function declaration and returns the function name and cycript type
		If load is true, tries to load it into cycript using utils.exec
		
		Usage:
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
		var rType = utils.applyTypedefs(match[1]);
		var name = match[2];
		var args = match[3];

		var argsRe = /([^,]+)(?:,|$)/g;
		var argsTypes = [];
		while((match = argsRe.exec(args)) !== null) {
			var type = utils.applyTypedefs(match[1]);
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
			throw "Function couldn't be found with dlsym!";
		}

		return [name, encodeString];
	};
	
	/*
		Loads the function declaration in the defs array using utils.exec and exposes to cycript's global scope
		Is automatically called if shouldLoadCFuncs is true
	*/
	utils.funcs = {};
	utils.loadfuncs = function(expose) {
		for(var i = 0; i < CFuncsDeclarations.length; i++) {
			try {
				var o = utils.include(CFuncsDeclarations[i], true);
				utils.funcs[o[0]] = o[1];
				if(expose) {
					Cycript.all[o[0]] = o[1];
				}
			} catch(e) {
				system.print("Failed to load function: " + i);
				try {
					system.print(utils.include(CFuncsDeclarations[i]));
				} catch(e2) {
					
				}
			}
		}
	};
	
	/*
		Calculates the size of a type like the C operator sizeof
		
		Usage:
			cy# utils.sizeof(int)
			4
			cy# utils.sizeof(@encode(void *))
			8
			cy# utils.sizeof("mach_vm_address_t")
			8
	*/
	utils.sizeof = function(type) {
		if(typeof type === "string") {
			type = utils.applyTypedefs(type);
			type = utils.exec("@encode(" + type + ")");
		}
		
		// (const) char * has "infinite" preceision
		if(type.toString().slice(-1) === "*") {
			return utils.sizeof(@encode(void *));
		}
		
		// float and double
		if(type.toString() === @encode(float).toString()) {
			return 4;
		} else if (type.toString() === @encode(double).toString()) {
			return 8;
		}

		var typeInstance = type(0);
		
		if(typeInstance instanceof Object) {
			// Arrays
			if("length" in typeInstance) {
				return typeInstance.length * utils.sizeof(typeInstance.type);
			}
			
			// Structs
			if(typeInstance.toString() === "[object Struct]") {
				var typeStr = type.toString();
				var arrayTypeStr = "[2" + typeStr + "]";
				var arrayType = new Type(arrayTypeStr);
				
				var arrayInstance = new arrayType;
				
				return @encode(void *)(&(arrayInstance[1])) - @encode(void *)(&(arrayInstance[0]));
			}
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
	
	/*
		Logs a specific message sent to an instance of a class like logify.pl in theos
		Requires Cydia Substrate (com.saurik.substrate.MS) and NSLog (org.cycript.NSLog) modules
		Returns the old message returned by MS.hookMessage (Note: this is not just the old message!)
		
		Usage:
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
		Calls a C function by providing its name and arguments
		Doesn't support structs
		Return value is always a void pointer
		
		Usage:
			cy# utils.apply("printf", ["%s %.3s, %d -> %c, float: %f\n", "foo", "barrrr", 97, 97, 1.5])
			foo bar, 97 -> a, float: 1.500000
			0x22
	*/
	utils.apply = function(fun, args) {
		if(!(args instanceof Array)) {
			throw "Args needs to be an array!";
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
			throw "Function not found!";
		}

		return type(fun).apply(null, args);
	};
	
	/*
		Converts a string (char *) to a void pointer (void *)
		You can't cast to strings to void pointers and vice versa in cycript. Blame saurik.
		
		Usage:
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
		
		Usage:
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
		
		Usage:
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
		Determines in a safe way if the memory location contains an Objective-C object

		Usage:
			cy# utils.isObject(0)
			false
			cy# utils.isObject(0x1337)
			false
			cy# utils.isObject(NSObject)
			true
			cy# utils.isObject(objc_getMetaClass(NSObject))
			true
			cy# utils.isObject([new NSObject init])
			true
			cy# var a = malloc(100); utils.isObject(a)
			false
			cy# *@encode(void **)(a) = NSObject; utils.isObject(a)
			true
	*/
	utils.isObject = function(obj) {
		obj = @encode(void *)(obj);
		var lastObj = -1;
		
		function objc_isa_ptr(obj) {
			// See http://www.sealiesoftware.com/blog/archive/2013/09/24/objc_explain_Non-pointer_isa.html
			var objc_debug_isa_class_mask = 0x00000001fffffffa;
			obj = (obj & 1)? (obj & objc_debug_isa_class_mask): obj;
			
			if((obj & (utils.sizeof(@encode(void *)) - 1)) != 0) {
				return null;
			} else {
				return obj;
			}
		}
		
		function ptrValue(obj) {
			return obj? obj.valueOf(): null;
		}
		
		var foundMetaClass = false;
		
		for(obj = objc_isa_ptr(obj); utils.isMemoryReadable(obj); ) {
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
		
		if(!utils.isMemoryReadable(obj_class)) {
			return false;
		}
		
		var metaclass = objc_isa_ptr(@encode(void **)(obj_class)[0]);
		var superclass = objc_isa_ptr(@encode(void **)(obj_class)[1]);
		
		return ptrValue(obj) == ptrValue(metaclass) && superclass == null;
	};
	
	/*
		Creates a cycript struct type from a C struct definition
		
		Usage:
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
		
		if(!name) {
			name = "struct" + Math.floor(Math.random() * 100000);
		}
		var typeStr = "{" + name + "=";
		
		while((match = fieldRe.exec(str)) !== null) {
			var fieldType = utils.applyTypedefs(match[1]);
			var fieldName = match[2];
			var encodedType = utils.exec("@encode(" + fieldType + ")").toString();
			
			typeStr += '"' + fieldName + '"' + encodedType;
		}
		
		typeStr += "}";
		
		var t = new Type(typeStr);
		Cycript.all[name] = t;
		return t;
	};
	
	/*
		Dumps all UI/NS Image instances to a temporary folder
		Optionally takes a filter function to filter which images to dump
		
		Usage:
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
			throw "No images found!"
		}
		
		var template = utils.str2voidPtr("/tmp/cycript-images-XXXXXX");
		utils.apply("mkdtemp", [template]);
		var dir = utils.voidPtr2str(template);

		for(var i = 0; i < images.length; i++) {
			data = [images[i] TIFFRepresentation];
			[data writeToFile:dir + "/" + i + ".tiff" atomically:YES];
		}
		
		return images.length + " images written to " + dir;
	}
	
	var app_class = ObjectiveC.classes["UIApplication"] || ObjectiveC.classes["NSApplication"];
	var app = app_class && [app_class sharedApplication];
	
	/*
		Uses a heuristic method to determine if the object's class is a standard one
		
		Usage:
			cy# @implementation TestClass : NSObject {} @end
			#"TestClass"
			cy# [new NSObject, [], "foo", new TestClass].map(utils.is_not_standard_class)
			[false,true,false,true]
	*/
	utils.is_not_standard_class = function(obj) {
		var classname = [obj className];
		while(classname[0] == '_') {
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
		
		Usage:
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
		Also filter outs classes which are "standard"
		
		Usage:
			cy# utils.find_interesting_view_classes().length
			9
	*/
	utils.find_interesting_view_classes = function() {
		var views = utils.find_subviews(utils.is_standard_class);
		var classes = views.map(x => x.className.toString());
		
		var interesting_classes = classes.filter(x => classes.indexOf(x) === classes.lastIndexOf(x));
		
		return interesting_classes;
	};
	
	/*
		Like utils.find_interesting_view_classes but for viewcontroller classes
	*/
	utils.find_interesting_viewcontroller_classes = function() {
		var views = utils.find_subview_controllers(utils.is_standard_class);
		var classes = views.map(x => x.className.toString());
		
		var interesting_classes = classes.filter(x => classes.indexOf(x) === classes.lastIndexOf(x));
		
		return interesting_classes;
	};
	
	/*
		Recursively returns the superviews of the view
		
		Usage:
			cy# utils.view_hierarchy(UIApp.keyWindow.subviews[0].subviews[0])
			["", "", ""]
	*/
	utils.view_hierarchy = function(view) {
		var arr = [];
		do {
			arr.unshift(view);
		} while(view = view.superview);
		
		return arr;
	};
	
	/*
		Determines if UI/NS View is on the screen
		
		Usage:
			cy# utils.is_on_screen(UIApp.keyWindow)
			true
			cy# utils.is_on_screen([new UIView init])
			false
	*/
	utils.is_on_screen = function(view) {
		var hierarchy = utils.view_hierarchy(view);
		
		return [hierarchy[hierarchy.length - 1] isEqual:app.keyWindow];
	};
	
	/*
		Returns the common superview of the two views
		and two integers with the distance between the views and the superview
		
		Usage:
			cy# rootview = [new UIView init]
			...
			cy# subview1 = [new UIView init]; [rootview addSubview:subview1];
			cy# subview2 = [new UIView init]; [rootview addSubview:subview2];
			cy# subview22 = [new UIView init]; [subview2 addSubview:subview22];
			cy# utils.view_relation(subview1, subview22)
			[#"<NSView: 0x100509ad0>",1,2]
	*/
	utils.view_relation = function(view1, view2) {
		var view_hierarchy1 = utils.view_hierarchy(view1);
		var view_hierarchy2 = utils.view_hierarchy(view2);
		
		var i;
		for(i = 0; [view_hierarchy1[i] isEqual:view_hierarchy2[i]]; i++) {
		}
		
		if(i === 0) {
			throw 'No relation!'
		}
		
		return [view_hierarchy1[i - 1], view_hierarchy1.length - i, view_hierarchy2.length - i];
	};
	
	/*
		Returns a pointer to type with a size of size * utils.sizeof(type)

		Usage:
			cy# arr = utils.makeArray(int, 4)
			&0
			cy# arr[1] = 100
			100
	*/
	utils.makeArray = function(type, size) {
		var mem = malloc(size * utils.sizeof(type));
		return type.pointerTo()(mem); 
	};
	
	/*
		Returns a pointer to type initialized with val

		Usage:
			cy# ptr = utils.pointerTo(int, 1337)
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
		
		Usage:
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
		var mibLenPtr = utils.pointerTo(@encode(uint64_t), mibLen);
		var err = utils.apply("sysctlnametomib", ["sysctl.proc_cputype", mib, mibLenPtr]);
		
		if(err !== null) {
			free(mib);
			free(mibLenPtr);
			throw "Error calling sysctlnametomib!";
		}
		
		mibLen = *mibLenPtr;
		free(mibLenPtr);
		mib[mibLen] = utils.apply("getpid", []);
		mibLen++;

		current_arch = utils.makeStruct("cpu_type_t type; cpu_subtype_t subtype;", "current_arch");
		archType = new current_arch;
		archTypeSizePtr = utils.pointerTo(@encode(uint64_t), utils.sizeof(current_arch));
		err = utils.apply("sysctl", [mib, mibLen, archType, archTypeSizePtr, 0, 0]);
		
		free(mib);
		free(archTypeSizePtr);
		if(err != null) {
			free(archType);
			throw "Error calling sysctl!";
		}
		
		var ret = [archType->type, archType->subtype];
		free(archType);

		return ret;
	};
	
	/*
		Returns a string containing the address and path to every loaded image in the process
		
		cy# ?expand
		expand == true
		cy# utils.get_dyld_info()
		"
		
		"
	*/
	utils.get_dyld_info = function() {
		var mach_header = utils.makeStruct("uint32_t magic; cpu_type_t cputype; cpu_subtype_t cpusubtype; uint32_t filetype; uint32_t ncmds; uint32_t sizeofcmds; uint32_t flags;", "mach_header");
		var dyld_image_info = utils.makeStruct("const struct mach_header* imageLoadAddress; const char* imageFilePath; uintptr_t imageFileModDate;", "dyld_image_info");
		var dyld_all_image_infos = utils.makeStruct("uint32_t version; uint32_t infoArrayCount; const struct dyld_image_info* infoArray;", "dyld_all_image_infos");

		var all_image_infos = dyld_all_image_infos.pointerTo()(utils.apply("_dyld_get_all_image_infos", []));
		var image_count = all_image_infos->infoArrayCount;
		var info_array = all_image_infos->infoArray;

		var log = "";

		for(var i = 0; i < image_count; i++) {
			var info = dyld_image_info.pointerTo()(&info_array[i]);
			
			log += "0x" + info->imageLoadAddress.valueOf().toString(16) + ": " + info->imageFilePath + "\n";
		}
		
		return log;
	};

	if(shouldExposeConsts) {
		for(var k in utils.constants) {
			Cycript.all[k] = utils.constants[k];
		}
	}
	
	if(shouldExposeFuncs) {
		for(var i = 0; i < funcsToExpose.length; i++) {
			var name = funcsToExpose[i];
			Cycript.all[name] = utils[name];
		}
	}
	
	if(shouldLoadCFuncs) {
		utils.loadfuncs(shouldExposeCFuncs);
	}
})(exports);
