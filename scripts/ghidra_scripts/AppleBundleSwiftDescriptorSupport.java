import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

abstract class AppleBundleSwiftDescriptorSupport extends AppleBundleSwiftMetadataSupport {

	private static final int SWIFT_FIELD_DESCRIPTOR_HEADER_SIZE = 16;
	private static final int SWIFT_FIELD_RECORD_MIN_SIZE = 12;
	private static final int SWIFT_CAPTURE_DESCRIPTOR_HEADER_SIZE = 12;

	@Override
	protected JsonArray buildSwiftFieldDescriptors() {
		JsonArray descriptors = new JsonArray();
		MemoryBlock block = findBlockByName("__swift5_fieldmd");
		if (block == null) {
			return descriptors;
		}
		Memory memory = currentProgram.getMemory();
		AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		long cursor = block.getStart().getOffset();
		long end = block.getEnd().getOffset();
		while (cursor + SWIFT_FIELD_DESCRIPTOR_HEADER_SIZE - 1 <= end && !monitor.isCancelled()) {
			long descriptor = cursor;
			try {
				RelativeString typeName = swiftRelativeString(memory, space, descriptor);
				int kind = readUnsignedShort(memory, space, descriptor + 8);
				int recordSize = readUnsignedShort(memory, space, descriptor + 10);
				long fieldCount = readUnsignedInt(memory, space, descriptor + 12);
				if (typeName.value.isEmpty() || recordSize < SWIFT_FIELD_RECORD_MIN_SIZE ||
					fieldCount > 16384) {
					cursor += 4;
					continue;
				}
				long recordsStart = descriptor + SWIFT_FIELD_DESCRIPTOR_HEADER_SIZE;
				long next = recordsStart + fieldCount * recordSize;
				if (next < cursor || next - 1 > end + 1) {
					cursor += 4;
					continue;
				}
				descriptors.add(swiftFieldDescriptorToJson(memory, space, descriptor, typeName,
					kind, recordSize, fieldCount, recordsStart));
				cursor = next;
			}
			catch (Exception ignored) {
				cursor += 4;
			}
		}
		return descriptors;
	}

	@Override
	protected JsonArray buildSwiftCaptureDescriptors() {
		JsonArray descriptors = new JsonArray();
		MemoryBlock block = findBlockByName("__swift5_capture");
		if (block == null) {
			return descriptors;
		}
		Memory memory = currentProgram.getMemory();
		AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		long cursor = block.getStart().getOffset();
		long end = block.getEnd().getOffset();
		while (cursor + SWIFT_CAPTURE_DESCRIPTOR_HEADER_SIZE - 1 <= end && !monitor.isCancelled()) {
			long descriptor = cursor;
			try {
				long captureTypeCount = readUnsignedInt(memory, space, descriptor);
				long metadataSourceCount = readUnsignedInt(memory, space, descriptor + 4);
				long bindingCount = readUnsignedInt(memory, space, descriptor + 8);
				if (!looksLikeCaptureDescriptor(captureTypeCount, metadataSourceCount, bindingCount)) {
					cursor += 4;
					continue;
				}
				long captureRecordsStart = descriptor + SWIFT_CAPTURE_DESCRIPTOR_HEADER_SIZE;
				long next = captureRecordsStart + captureTypeCount * 4;
				if (next < cursor || next - 1 > end + 1) {
					cursor += 4;
					continue;
				}
				JsonObject item = new JsonObject();
				item.addProperty("address", toHex(descriptor));
				item.addProperty("section", block.getName());
				item.addProperty("capture_type_count", captureTypeCount);
				item.addProperty("metadata_source_count", metadataSourceCount);
				item.addProperty("binding_count", bindingCount);
				item.add("capture_types", swiftCaptureTypesToJson(memory, space,
					captureRecordsStart, captureTypeCount));
				item.add("sample_xrefs", sampleReferences(space.getAddress(descriptor), 8)
					.getAsJsonArray("items"));
				descriptors.add(item);
				cursor = next;
			}
			catch (Exception ignored) {
				cursor += 4;
			}
		}
		return descriptors;
	}

	private JsonObject swiftFieldDescriptorToJson(Memory memory, AddressSpace space,
			long descriptor, RelativeString typeName, int kind, int recordSize, long fieldCount,
			long recordsStart) {
		JsonObject item = new JsonObject();
		item.addProperty("address", toHex(descriptor));
		item.addProperty("section", "__swift5_fieldmd");
		item.addProperty("kind", swiftFieldDescriptorKind(kind));
		item.addProperty("kind_value", kind);
		item.addProperty("field_record_size", recordSize);
		item.addProperty("field_count", fieldCount);
		item.add("mangled_type_name", typeName.toJson("mangled_type_name"));
		item.add("superclass", swiftNullableRelativeString(memory, space, descriptor + 4)
			.toJson("superclass"));
		JsonArray fields = new JsonArray();
		for (long index = 0; index < fieldCount; index++) {
			long record = recordsStart + index * recordSize;
			try {
				long flags = readUnsignedInt(memory, space, record);
				JsonObject field = new JsonObject();
				field.addProperty("index", index);
				field.addProperty("address", toHex(record));
				field.addProperty("flags", flags);
				field.addProperty("is_var", (flags & 0x2) != 0);
				field.addProperty("is_indirect_case", (flags & 0x4) != 0);
				field.add("mangled_type_name", swiftNullableRelativeString(memory, space,
					record + 4).toJson("mangled_type_name"));
				field.add("field_name", swiftNullableRelativeString(memory, space, record + 8)
					.toJson("field_name"));
				fields.add(field);
			}
			catch (Exception ignored) {
				JsonObject field = new JsonObject();
				field.addProperty("index", index);
				field.addProperty("address", toHex(record));
				field.addProperty("decode_error", true);
				fields.add(field);
			}
		}
		item.add("fields", fields);
		item.add("sample_xrefs", sampleReferences(space.getAddress(descriptor), 8)
			.getAsJsonArray("items"));
		return item;
	}

	private JsonArray swiftCaptureTypesToJson(Memory memory, AddressSpace space,
			long recordsStart, long count) {
		JsonArray types = new JsonArray();
		for (long index = 0; index < count; index++) {
			long record = recordsStart + index * 4;
			JsonObject item = new JsonObject();
			item.addProperty("index", index);
			item.addProperty("address", toHex(record));
			item.add("mangled_type_name", swiftNullableRelativeString(memory, space, record)
				.toJson("mangled_type_name"));
			types.add(item);
		}
		return types;
	}

	private boolean looksLikeCaptureDescriptor(long captureTypeCount, long metadataSourceCount,
			long bindingCount) {
		if (captureTypeCount == 0 && metadataSourceCount == 0 && bindingCount == 0) {
			return false;
		}
		if (captureTypeCount > 4096 || metadataSourceCount > 4096 || bindingCount > 4096) {
			return false;
		}
		return captureTypeCount > 0;
	}

	private RelativeString swiftRelativeString(Memory memory, AddressSpace space, long fieldAddress)
			throws MemoryAccessException {
		long target = resolveSwiftRelativePointer(memory, space, fieldAddress);
		if (target == 0) {
			return new RelativeString(fieldAddress, 0, "", "");
		}
		return new RelativeString(fieldAddress, target, readCString(memory, space, target),
			primarySymbolName(space, target));
	}

	private RelativeString swiftNullableRelativeString(Memory memory, AddressSpace space,
			long fieldAddress) {
		try {
			return swiftRelativeString(memory, space, fieldAddress);
		}
		catch (Exception ignored) {
			return new RelativeString(fieldAddress, 0, "", "");
		}
	}

	private long resolveSwiftRelativePointer(Memory memory, AddressSpace space, long fieldAddress)
			throws MemoryAccessException {
		int relative = memory.getInt(space.getAddress(fieldAddress), false);
		if (relative == 0) {
			return 0;
		}
		return fieldAddress + relative;
	}

	private long readUnsignedInt(Memory memory, AddressSpace space, long offset)
			throws MemoryAccessException {
		return memory.getInt(space.getAddress(offset), false) & 0xffffffffL;
	}

	private int readUnsignedShort(Memory memory, AddressSpace space, long offset)
			throws MemoryAccessException {
		return memory.getShort(space.getAddress(offset), false) & 0xffff;
	}

	private String readCString(Memory memory, AddressSpace space, long offset) {
		StringBuilder builder = new StringBuilder();
		try {
			for (int index = 0; index < 4096; index++) {
				byte value = memory.getByte(space.getAddress(offset + index));
				if (value == 0) {
					break;
				}
				builder.append((char) (value & 0xff));
			}
		}
		catch (MemoryAccessException ignored) {
			return "";
		}
		return trimSwiftMetadataPrefix(builder.toString());
	}

	private String primarySymbolName(AddressSpace space, long offset) {
		try {
			Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(space.getAddress(offset));
			return symbol == null ? "" : empty(symbol.getName());
		}
		catch (Exception ignored) {
			return "";
		}
	}

	private String trimSwiftMetadataPrefix(String value) {
		String result = empty(value);
		while (!result.isEmpty() && (result.charAt(0) == '\001' || result.charAt(0) == '\002')) {
			result = result.substring(1);
		}
		return result;
	}

	private String swiftFieldDescriptorKind(int kind) {
		switch (kind) {
			case 0:
				return "struct";
			case 1:
				return "class";
			case 2:
				return "enum";
			case 3:
				return "multi_payload_enum";
			case 4:
				return "protocol";
			case 5:
				return "class_protocol";
			case 6:
				return "objc_protocol";
			case 7:
				return "objc_class";
			default:
				return "unknown";
		}
	}

	private String toHex(long value) {
		return "0x" + Long.toHexString(value);
	}

	private class RelativeString {
		private final long fieldAddress;
		private final long targetAddress;
		private final String value;
		private final String symbolName;

		private RelativeString(long fieldAddress, long targetAddress, String value,
				String symbolName) {
			this.fieldAddress = fieldAddress;
			this.targetAddress = targetAddress;
			this.value = value == null ? "" : value;
			this.symbolName = symbolName == null ? "" : symbolName;
		}

		private JsonObject toJson(String role) {
			JsonObject item = new JsonObject();
			item.addProperty("role", role);
			item.addProperty("field_address", "0x" + Long.toHexString(fieldAddress));
			item.addProperty("target_address",
				targetAddress == 0 ? "" : "0x" + Long.toHexString(targetAddress));
			item.addProperty("value", value);
			item.addProperty("symbol_name", symbolName);
			item.addProperty("display_value", symbolName.isEmpty() ? value : symbolName);
			return item;
		}
	}

}
