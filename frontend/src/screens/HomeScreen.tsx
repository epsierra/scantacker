import { useEffect, useState } from "react";
import logo from "../assets/images/logo-universal.png";
import { FindInterfaces,GetPackets, PauseScan } from "../../wailsjs/go/main/App";
import {EventsOff, EventsOn} from "../../wailsjs/runtime";
import { useNavigate } from "react-router";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import {
  Table,
  TableBody,
  TableCell,
  TableFooter,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Pause, Play, StopCircle, StopCircleIcon } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { pcap} from "wailsjs/go/models";

type PacketSummary = {
    ID:string
	Timestamp:Date
    SeqNumber:number
	SrcIP :string   
	DstIP:string
	SrcPort:number
    SrcMac:string
    DstMac:string
	DstPort:number
	Protocol:string
	Length:number
	ReadableData:string
    Info:string
	Bytes:number[]
}

function HomeScreen() {
  const [devices, setDevices] = useState<pcap.Interface[]>([]);
  const [activeDevice, setActiveDevice] = useState<string>("all");
  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<PacketSummary | null>(null);
  const [name, setName] = useState("");
  const updateName = (e: any) => setName(e.target.value);
  const navigate = useNavigate();

  useEffect(()=>{
      FindInterfaces().then(result =>{
        setDevices(result)
        console.log(result)
      })
  },[])

  useEffect(()=>{
    GetPackets("all").then(()=> setActiveDevice("all")
    ).catch(err =>{
        console.warn(err)
    })
},[])


  useEffect(()=>{
      EventsOn?.("packet",function(data){
        setPackets(prev => [data,...prev])
        // console.log(data)
      })

      return ()=>{
        EventsOff("packet")
      }

},[EventsOn])

  const handleFilterByDevice = (dev:string) => {
    GetPackets(dev).then(()=> setActiveDevice(dev)
    ).catch(err =>{
        console.warn(err)
    })
  };

  const handleStop = ()=>{
      PauseScan().catch((err)=>{
        console.error(err)
      })
  }

  return (
    <div className="bg-background grid grid-cols-dashboard">
      <div className="min-w-10 flex flex-col items-center mx-auto p-4 bg-background border-r">
        <h4 className="my-2 text-primary font-black">Interfaces</h4>
        <div className="gap-2">
          <div className="my-1">
            <Button
              onClick={() => handleFilterByDevice("all")}
              className="rounded w-full"
              variant={activeDevice === "all" ? "default" : "ghost"}
            >
              all
            </Button>
          </div>
          {devices.map((dev, index) => {
            return (
              <div key={dev.Name + index} className="my-1">
                <Button
                  onClick={() => handleFilterByDevice(dev.Name)}
                  className="rounded w-full"
                  variant={activeDevice === dev.Name ? "default" : "ghost"}
                >
                  {dev.Name}
                </Button>
              </div>
            );
          })}
        </div>
      </div>
      <div>
        <div className="w-full flex flex-row justify-between">
          <div className="w-full flex flex-row p-2 gap-2">
            <Input className="max-w-md" />
            <Button className="rounded">Filter</Button>
            <Button
              size="icon"
              variant="outline"
              className="rounded bg-background"
            >
              <Play />
            </Button>
            <Button
              onClick={handleStop}
              size="icon"
              variant="outline"
              className="rounded bg-background"
            >
              <Pause />
            </Button>
            <Button onClick={handleStop} size="icon" variant="outline" className="rounded">
              <StopCircleIcon />
            </Button>
          </div>
          <div className="w-full flex items-center justify-end space-x-2 mr-10">
            <label
              htmlFor="terms"
              className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
            >
              Enable promiscuous mode
            </label>
            <Checkbox id="terms" />
          </div>
        </div>
        <ResizablePanelGroup
          direction="vertical"
          className="rounded-lg md:min-w-[450px]"
        >
          <ResizablePanel defaultSize={65}>
            <div className="flex h-full justify-center p-6">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Selected</TableHead>
                    <TableHead>Time</TableHead>
                    <TableHead>Source IP</TableHead>
                    <TableHead>Destination IP</TableHead>
                    <TableHead>Source Mac</TableHead>
                    <TableHead>Destination Mac</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Info</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {packets.map((packet,index) => (
                    <TableRow key={packet.ID} onClick={()=> setSelectedPacket(packet)}>
                      <TableCell className="text-left">
                        <Checkbox onClick={()=> setSelectedPacket(packet)} checked={selectedPacket?.ID === packet.ID} />
                      </TableCell>
                   
                      <TableCell className="text-left">{(new Date(packet.Timestamp)).toDateString()}</TableCell>
                      <TableCell className="text-left">{packet.SrcIP}</TableCell>
                      <TableCell className="text-left">{packet.DstIP}</TableCell>
                      <TableCell className="text-left">{packet.SrcMac}</TableCell>
                      <TableCell className="text-left">{packet.DstMac}</TableCell>
                      <TableCell className="text-left">{packet.Protocol}</TableCell>
                      <TableCell className="text-left">{packet.Info}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
                <TableFooter></TableFooter>
              </Table>
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel defaultSize={30}>
            <div className="flex h-full items-center justify-center p-6">
              <ResizablePanelGroup
                direction="horizontal"
                className="h-full rounded-lg md:min-w-[450px]"
              >
                <ResizablePanel defaultSize={60}>
                  <div className="flex h-full items-start justify-center p-4">
                  {selectedPacket?.ReadableData}
                  </div>
                </ResizablePanel>
                <ResizableHandle withHandle />
                <ResizablePanel defaultSize={30}>
                  <div className="flex h-full items-start justify-center p-4">
                    <p className="text-wrap">
                    {selectedPacket?.Bytes}
                    </p>
                  </div>
                </ResizablePanel>
              </ResizablePanelGroup>
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </div>
  );
}

export default HomeScreen;
