<#

.SYNOPSIS
PowerShell Script to gather weak (unencrypted) AWS resources

.DESCRIPTION
Uses AWS PowerShell Module to probe AWS account for unencrypted AWS resources.  Currently supports:
    - S3 Buckets
    - EBS Volumes
    - EBS Snapshots
    - RDS Storage
    - RDS Snapshots
    - SQS Queues
    - Kinesis
    - Elastic Load Balancer
    - Simple Notification Service
    **Working on adding RedShift - Needs testing on working cluster

.EXAMPLE

=Standard Output to terminal=
./FindWeakAWSResources.ps1 -accessKeyId XxXxXxXxXx -secretAccessKey XxXxXxXx -DefaultRegion us-east-2

=Export Results to file=
./FindWeakAWSResources.ps1 -accessKeyId XxXxXxXxXx -secretAccessKey XxXxXxXx -DefaultRegion us-east-2 -exportResults

.NOTES
Script requires AWS PowerShell module. To verify it's currently installed run 'Get-Module AWSPowerShell'
For information on installing visit https://docs.aws.amazon.com/powershell/latest/userguide/pstools-getting-set-up-windows.html

.VERSION 2.0
  - Added ELB and SNS Support

Created by Joe Sadler

#>


# User Defined Environmental Variables
param(

# Get AWS Credentials
[Parameter(Mandatory)]
$accesKeyId,

[Parameter(Mandatory)]
$secretAccessKey,

# Get Region.  Default to us-east-2
[Parameter(Mandatory)]
[ValidateSet("us-east-1", "us-east-2", "us-west-1", "us-west-2", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "cn-north-1", "cn-northwest-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "sa-east-1", "us-gov-east-1", "us-gov-west-1")]
$DefaultRegion,

# Optional switch to export results
[switch]
$exportResults
)


# Only run script if AWS PowerShell Module is installed
If(!(Get-Module -Name AWSPowerShell)){
    Write-Output "AWS PowerShell Module is not installed.  Run 'Install-Module AWSPowerShell' to continue."
    break
}


#Set AWS credentials and region
Set-AWSCredentials -AccessKey $accesKeyId -SecretKey $secretAccessKey
Set-DefaultAWSRegion -Region $DefaultRegion

#>


# Set AWS Account Number
$accountId = (get-ec2securitygroup -GroupNames "default")[0].OwnerId




# Get S3 Buckets Encryption Status
Try{
    $s3Buckets = (Get-S3Bucket).BucketName
    $unencryptedS3Buckets = @()

    Foreach ($bucket in $s3Buckets){
        If(!(Get-S3BucketEncryption -BucketName $bucket).ServerSideEncryptionRules){
            $unencryptedS3Buckets += $bucket
        }
    }
}
Catch{
    $unencryptedS3Buckets = "ERROR: Couldn't connect to Amazon Simple Storage Service (S3)"

}




# Get EBS Encryption Status
Try{
    $EBSVolumes = (Get-EC2Volume).VolumeId
    $unencryptedEBSVolumes = @()

    Foreach ($vol in $EBSVolumes){
        If((Get-EC2Volume -VolumeId $EBSVolumes).Encrypted -eq $false){
            $unencryptedEBSVolumes += $vol
        }
    }
}
Catch{
    $unencryptedEBSVolumes= "ERROR: Couldn't connect to Elastic Cloud Compute (EC2)"
}




# Get EBS Snapshot Encryption Status
Try{
    $EBSSnaps = (Get-EC2Snapshot -OwnerId $accountId).SnapshotId
    $unencryptedEBSSnaps = @()

    Foreach ($EBSSnap in $EBSSnaps){
        If (((Get-EC2Snapshot -SnapshotId $EBSSnap ).Encrypted) -eq $false){
            $unencryptedEBSSnaps += $EBSSnap
        }
    }
}
Catch{
    $unencryptedEBSSnaps = "ERROR: Couldn't connect to Elastic Cloud Compute (EC2) Service"
}




# Get RDS Encryption Status
Try{
    $RDSInstances = (Get-RDSDBInstance).DBInstanceIdentifier
    $unencryptedRDSStorage = @()

    Foreach ($instance in $RDSInstances){
        If((Get-RDSDBInstance -DBInstanceIdentifier $RDSInstances).StorageEncrypted -eq $false){
            $unencryptedRDSStorage += $instance    
        }
    }
}
Catch{
    $unencryptedRDSStorage = "ERROR: Couldn't connect to RDS Service"
}




# Get RDS Snapshot Encryption Status
Try{
    $RDSSnap = (Get-RDSDBSnapshot).DBSnapshotIdentifier
    $unencryptedRDSSnapshots = @()

    Foreach ($snap in $RDSSnap){
        If((Get-RDSDBSnapshot -DBSnapshotIdentifier $snap).Encrypted -eq $false){
            $unencryptedRDSSnapshots += $snap
        }
    }
}
Catch{
    $unencryptedRDSStorage = "ERROR: Couldn't connect to RDS Service"
}




# Get SQS Queue Encryption Status
Try{
    $Queues = (Get-SQSQueue)
    $unencryptedSQSQueues = @()

    Foreach ($Queue in $Queues){
        if (!(((Get-SQSQueueAttribute -QueueUrl $Queue -AttributeName KmsMasterKeyId).Attributes).Keys -like "KmsMasterKeyId*" )) {
            $unencryptedSQSQueues += $Queue
        }
    }
}
Catch{
    $unencryptedSQSQueues = "ERROR: Couldn't connect to SQS Service"
}



# Get Kinesis Encryption Status
Try {
    $KinesisStreams = @(Get-KINStreamList).StreamNames
    $UnencryptedKinesisStreams = @()

    Foreach($stream in $KinesisStreams){
        If((Get-KINStreamSummary -StreamName $KinesisStreams).EncryptionType -eq "NONE"){
            $UnencryptedKinesisStreams += $stream
        }

    }
}
Catch {
    $UnencryptedKinesisStreams = "ERROR: Couldn't connect to Kinesis Service"
}


# Get ELB Encryption Status
Try{
    $ELBs = (Get-ELB2LoadBalancer).LoadBalancerArn
    $unencryptedELBs=@()

    foreach ($ELB in $ELBs){

    $protocols = (Get-ELB2Listener -LoadBalancerArn $ELB).Protocol
        Foreach ($protocol in $protocols){
            if ($protocol -ne "HTTPS"){
                $unencryptedELBs += $ELB
            }
        }
    }
}
Catch{
    $unencryptedELBs = "ERROR: Couldn't connect to AWS to pull ELB information"
    }



# Get SNS Encryption Status
Try{
    $SNSs = (Get-SNSTopic).TopicArn
    $unencryptedSNSs = @()

    Foreach ($SNS in $SNSs){
        If((Get-SNSTopicAttribute -TopicArn $SNS).KmsMasterKeyId -eq $null){
            $unencryptedSNSs += $SNS
        }
    }
}

Catch{
    $unencryptedSNSs = "ERROR: Couldn't connect to Simple Notification Service (SNS)"
}




<#
# Get RedShift Cluster Encryption Status
Try{
    $redshiftClusters = (Get-RSCluster).ClusterIdentifier
    $unencryptedRedshift = @()

    Foreach ($redshift in $redshiftClusters){
        If((Get-RSCluster -ClusterIdentifier $redshift).KmsKeyId -ne $null){
            $unencryptedRedshift += $redshift
        }
    }
}
Catch{
    $unencryptedRedshift = "ERROR: Couldn't connect to RDS Service"
}
#>



# Build a Presentable Table
$obj = [ordered]@{
    "AWS Account Number:" = $accountId
    "AWS Region:" = $DefaultRegion
    "Unencrypted S3 Bucket(s):" = $unencryptedS3Buckets
    "Unencrypted EBS Volume(s):" = $unencryptedEBSVolumes
    "Unencrypted EBS Snapshot(s):" = $unencryptedEBSSnaps
    "Unencrypted RDS Storage: " = $unencryptedRDSStorage
    "Unencrypted RDS Snapshot(s):" = $unencryptedRDSSnapshots
    "Unencrypted SQS Queue(s):" = $unencryptedSQSQueues
    "Unencrypted Kinesis Streams: " = $UnencryptedKinesisStreams
    "Unencrypted ELBs: " = $unencryptedELBs
    "Unencrypted SNS: " = $unencryptedSNSs
    #"Unencrypted Redshift Cluster:" = $unencryptedRedshift + " This search needs testing with working redshift cluster"
}


# Output table to file if 'exportResults' switch is used
If($exportResults){

    $SaveChooser = New-Object -TypeName System.Windows.Forms.SaveFileDialog
    $SaveChooser.filter = “Text files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|All files (*.*)|*.*”
    Write-Output "Select a location and filename for your exported results."
    $SaveChooser.ShowDialog()
    $obj | ft -AutoSize -HideTableHeaders | Out-File $SaveChooser.Filename

}

# Display table in console if no 'exportResults' (Default Behavior)
Else{
    $obj | ft -AutoSize -HideTableHeaders
    }
