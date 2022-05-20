local function print_r(arr, indentLevel)
    if type(arr) ~= "table" then
      return tostring(arr)
    end
  
    local str = ""
    local indentStr = "#"
  
    if(indentLevel == nil) then
      return print_r(arr, 0)
    end
  
    for i = 0, indentLevel do
      indentStr = indentStr.."\t"
    end
  
    for index,Value in pairs(arr) do
      if type(Value) == "table" then
        str = str..indentStr..index..": \n"..print_r(Value, (indentLevel + 1))
      else
        str = str..indentStr..index..": "..tostring(Value).."\n"
      end
    end
    return str
  end

return {
    print_r = print_r
}