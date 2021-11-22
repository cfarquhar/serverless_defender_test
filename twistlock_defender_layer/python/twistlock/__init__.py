import importlib
import ctypes, os, json, subprocess # Subprocess is imported to make sure it is hooked
libtw = None
# load_twistlock loads the twistlock libtw library and adds an interface for wrapping handlers
def load_twistlock(path):
	global libtw
	path += '/twistlock/libtw_serverless.so'
	if not os.path.exists(path):
		return False
	# Load twistlock shared object
	libtw = ctypes.CDLL(path, mode = ctypes.RTLD_LOCAL)
	# Check handler request should be exported from the shared object, receives 2 strings:
	# -event - the event json
	# -context - the function json containing the aws request ID and invoked function ARN
	# with their length and returns a boolean
	libtw.check_request.argtypes=[ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
	libtw.check_request.restype=ctypes.c_bool
	return True

#  wrap_handler returns a function that wraps the original handler
def wrap_handler(original_handler):
	# twistlock_handler checks handler input for attacks and calls the original handler
	def twistlock_handler(event, context):
		# Checks handler input for attacks and calls the original handler
		json_event = json.dumps(event).encode('utf-8')
		# context isn't serializable, extracting required fields
		# ref: https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
		function_context = {}
		function_context['AwsRequestID'] = context.aws_request_id
		function_context['InvokedFunctionArn'] = context.invoked_function_arn
		json_context = json.dumps(function_context).encode('utf-8')
		# Check request returns whether to block or approve the request
		if libtw.check_request(ctypes.create_string_buffer(json_event), len(json_event), ctypes.create_string_buffer(json_context), len(json_context)):
			response = None
			# Ignore all errors that relate to custom response
			try:
				response = json.loads(os.environ['TW_CUSTOM_RESPONSE'])
			except:
				None
			return response
		return original_handler(event, context)
	return twistlock_handler

# If twistlock layer is used, the shared object will be in /opt, otherwise in the folder saved in LAMBDA_TASK_ROOT
# Refs:
# https://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html
# https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html
if not load_twistlock(os.environ['LAMBDA_TASK_ROOT']) and not load_twistlock('/opt'):
	raise ValueError('[Twistlock] Failed to find Twistlock runtime')


#
# get_original_handler replaces the original handler with Twistlock protected handler
# Gets the invokable function that's given in the environment ORIGINAL_HANDLER
#
def get_original_handler():
	# Check that the user defined ORIGINAL_HANDLER env var
	if 'ORIGINAL_HANDLER' not in os.environ or not os.environ['ORIGINAL_HANDLER']:
		raise ValueError('Must provide ORIGINAL_HANDLER environment variable')

	# support multiple dots module path
	tok = os.environ['ORIGINAL_HANDLER'].rsplit('.',1)
	if len(tok) != 2:
		raise ValueError('Wrong handler format: %s' % os.environ['ORIGINAL_HANDLER'])
	module_path, handler_name = tok
	module_path = module_path.replace('/', '.')

	# Import the file, and save the original handler
	try:
		module = importlib.import_module(module_path)
	except ImportError:
		raise ImportError('Failed to import module: %s' % module_path)

	try:
		original_handler = getattr(module, handler_name)
	except AttributeError:
		raise AttributeError('No handler %s in module %s' % (handler_name, module_path))

	return original_handler

# handler wraps the original handler with Twistlock protection layer
original_handler = get_original_handler()
def handler(event, context):
	return wrap_handler(original_handler)(event, context)
