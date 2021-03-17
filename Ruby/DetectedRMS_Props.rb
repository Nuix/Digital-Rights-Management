RMS_Terms=[
	"Microsoft Rights Label",
	"DRM Server"
]

RMSTypes=[
	"application/vnd.ms-ole2-encrypted-package"
]


def nuix_worker_item_callback(worker_item)
    worker_item.process_item=true
    item=worker_item.source_item
    if (RMSTypes.include? item.getType.getName)
		props=worker_item.getSourceItem().getProperties()
		name="Unknown"
		found=false
        begin
			if item.getBinary().isAvailable()
				data=item.getBinary().getBinaryData()
				raw_ascii=[]
				0.upto(data.getLength()-1) do | i|
					begin
						raw_ascii.push *data.read(i).chr()
					rescue RangeError => range_ex
						#don't error
					rescue Exception => ex
						worker_item.addTag("RMS|Errors scanning binary")
					end
				end
				full_text=raw_ascii.join()
				if(RMS_Terms.select{|term|full_text.include? term}.length == RMS_Terms.length)
					distribution_points=full_text.scan(/(?<=<DISTRIBUTIONPOINT>).*?(?=<\/DISTRIBUTIONPOINT>)/)
					if(distribution_points.length > 0)
						distribution_points.to_a.each do | distribution_point|
							type=distribution_point.match(/(?<=<OBJECT type=").*?(?=">)/)
							address=distribution_point.match(/(?<=<ADDRESS type="URL">).*?(?=<)/)
							props["RMS #{type}"]=address.to_s
							found=true
						end
					end
					matches=full_text.match(/\<ISSUER.*?<\/ISSUER>/)
					if(matches.length > 0)
						names=matches[0].match(/(?<=\<NAME\>).*(?=\<\/NAME\>)/)
						if(names.length > 0)
							name=names[0]
							props["RMS Issuer"]=name
							found=true
						end
					end
					if(found==true)
						worker_item.item_properties=props
						worker_item.addTag("RMS|Found")
					end
				end
			else
				worker_item.addTag("RMS|Binary is unavailable for item")
			end
		rescue Exception => e
			worker_item.addTag("RMS|Error extracting embedded items|[Item=#{item.name},Error=#{e.message},StackTrace=#{e.backtrace.inspect}]")
		end
    end
end