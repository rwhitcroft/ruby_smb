module RubySMB
class  Field
class  Composite < Field
  def to_binary_s
    result = ''
    children.each do |child|
      result += child.to_binary_s
    end
    result
  end
end
end
end
