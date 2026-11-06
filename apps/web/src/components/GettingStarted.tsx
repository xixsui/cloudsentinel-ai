"use client";
import {useEffect,useState} from "react";
import Link from "next/link";
import {api} from "@/lib/api";
type Status={finding_count:number;aws_connected:boolean;ai_configured:boolean;prowler_installed:boolean;scans:unknown[]};
export default function GettingStarted(){
 const [data,setData]=useState<Status|null>(null);
 useEffect(()=>{api<Status>("workspace/status").then(setData).catch(()=>{});},[]);
 if(!data||data.aws_connected||data.finding_count>0||data.scans.length>0)return null;
 return <div className="notice"><span>Get started: <Link href="/scans#import">upload a Prowler report</Link> or <Link href="/settings#aws">connect AWS</Link> to run a scan. AI setup is optional.</span></div>;
}
