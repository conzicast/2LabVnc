param(
  [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing

$iconSizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
$brandRed = [System.Drawing.ColorTranslator]::FromHtml('#E30613')
$disabledGray = [System.Drawing.ColorTranslator]::FromHtml('#687383')
$connectedGreen = [System.Drawing.ColorTranslator]::FromHtml('#087B46')

function New-TilePath {
  $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
  $inset = 0.32
  $tileSize = 15.36
  $diameter = 7.2
  $farEdge = $inset + $tileSize - $diameter
  $path.AddArc($inset, $inset, $diameter, $diameter, 180, 90)
  $path.AddArc($farEdge, $inset, $diameter, $diameter, 270, 90)
  $path.AddArc($farEdge, $farEdge, $diameter, $diameter, 0, 90)
  $path.AddArc($inset, $farEdge, $diameter, $diameter, 90, 90)
  $path.CloseFigure()
  return $path
}

function New-NumeralPath {
  $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
  $path.AddBezier(6.15, 5.35, 6.25, 3.70, 7.47, 2.65, 9.50, 2.65)
  $path.AddBezier(9.50, 2.65, 11.45, 2.65, 12.75, 3.70, 12.75, 5.18)
  $path.AddBezier(12.75, 5.18, 12.75, 6.55, 11.83, 7.28, 10.65, 8.02)
  $path.AddLine(10.65, 8.02, 9.42, 8.86)
  $path.AddLine(9.42, 8.86, 12.85, 8.86)
  $path.AddLine(12.85, 8.86, 12.85, 10.65)
  $path.AddLine(12.85, 10.65, 6.20, 10.65)
  $path.AddLine(6.20, 10.65, 6.20, 9.08)
  $path.AddLine(6.20, 9.08, 9.40, 6.86)
  $path.AddBezier(9.40, 6.86, 10.15, 6.34, 10.59, 5.90, 10.59, 5.37)
  $path.AddBezier(10.59, 5.37, 10.59, 4.75, 10.15, 4.45, 9.49, 4.45)
  $path.AddBezier(9.49, 4.45, 8.79, 4.45, 8.27, 4.83, 8.22, 5.50)
  $path.CloseFigure()
  return $path
}

function Draw-Polygon {
  param(
    [System.Drawing.Graphics]$Graphics,
    [System.Drawing.Brush]$Brush,
    [float[]]$Vertices
  )
  [System.Drawing.PointF[]]$points = for ($index = 0; $index -lt $Vertices.Length; $index += 2) {
    [System.Drawing.PointF]::new($Vertices[$index], $Vertices[$index + 1])
  }
  $Graphics.FillPolygon($Brush, $points)
}

function New-IconBitmap {
  param(
    [int]$Size,
    [ValidateSet('viewer', 'server', 'connected', 'disabled')]
    [string]$Variant
  )

  # Render the same artwork directly at each size. Keep the shield outside the
  # numeral's main strokes so it remains legible in the notification area.
  $bitmap = [System.Drawing.Bitmap]::new(
    $Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $tileColor = if ($Variant -eq 'disabled') { $disabledGray } else { $brandRed }
  $tileBrush = [System.Drawing.SolidBrush]::new($tileColor)
  $greenBrush = [System.Drawing.SolidBrush]::new($connectedGreen)
  $whiteBrush = [System.Drawing.Brushes]::White
  $tile = New-TilePath
  $numeral = New-NumeralPath
  try {
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.ScaleTransform($Size / 16.0, $Size / 16.0)
    $graphics.FillPath($tileBrush, $tile)
    Draw-Polygon $graphics $whiteBrush @(
      2.85, 2.65, 4.86, 2.65, 4.86, 11.72, 12.85, 11.72, 12.85, 13.68, 2.85, 13.68)
    $graphics.FillPath($whiteBrush, $numeral)
    if ($Variant -eq 'connected') {
      Draw-Polygon $graphics $whiteBrush @(
        12.83, 10.02, 15.95, 11.17, 15.66, 13.78, 12.83, 15.94, 9.98, 13.78, 9.70, 11.17)
      Draw-Polygon $graphics $greenBrush @(
        12.83, 11.02, 15.00, 11.81, 14.82, 13.29, 12.83, 14.83, 10.83, 13.29, 10.67, 11.81)
    }
  } finally {
    $numeral.Dispose()
    $tile.Dispose()
    $greenBrush.Dispose()
    $tileBrush.Dispose()
    $graphics.Dispose()
  }

  return $bitmap
}
function Write-MultiSizeIcon {
  param(
    [string]$Path,
    [ValidateSet('viewer', 'server', 'connected', 'disabled')]
    [string]$Variant
  )

  $images = @()
  foreach ($size in $iconSizes) {
    $bitmap = New-IconBitmap $size $Variant
    $stream = [System.IO.MemoryStream]::new()
    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $images += [pscustomobject]@{
      Size = $size
      Bytes = $stream.ToArray()
    }
    $stream.Dispose()
    $bitmap.Dispose()
  }

  $output = [System.IO.File]::Create($Path)
  $writer = [System.IO.BinaryWriter]::new($output)
  $writer.Write([uint16]0)
  $writer.Write([uint16]1)
  $writer.Write([uint16]$images.Count)
  $dataOffset = 6 + (16 * $images.Count)
  foreach ($image in $images) {
    $dimension = if ($image.Size -eq 256) { 0 } else { $image.Size }
    $writer.Write([byte]$dimension)
    $writer.Write([byte]$dimension)
    $writer.Write([byte]0)
    $writer.Write([byte]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]32)
    $writer.Write([uint32]$image.Bytes.Length)
    $writer.Write([uint32]$dataOffset)
    $dataOffset += $image.Bytes.Length
  }
  foreach ($image in $images) {
    $writer.Write($image.Bytes)
  }
  $writer.Dispose()
  $output.Dispose()
}

function Write-Preview {
  param(
    [string]$Path,
    [ValidateSet('viewer', 'server', 'connected', 'disabled')]
    [string]$Variant
  )

  $bitmap = New-IconBitmap 256 $Variant
  $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
  $bitmap.Dispose()
}

function Write-AboutBitmap {
  param(
    [string]$Path,
    [int]$Width,
    [int]$Height,
    [ValidateSet('viewer', 'server')]
    [string]$Variant
  )

  $canvas = [System.Drawing.Bitmap]::new($Width, $Height)
  $graphics = [System.Drawing.Graphics]::FromImage($canvas)
  $graphics.Clear([System.Drawing.Color]::White)
  $graphics.InterpolationMode =
    [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $side = [Math]::Min($Width, $Height)
  $source = New-IconBitmap $side $Variant
  $left = [int](($Width - $side) / 2)
  $graphics.DrawImage($source, $left, 0, $side, $side)
  $canvas.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp)
  $source.Dispose()
  $graphics.Dispose()
  $canvas.Dispose()
}

$outputDirectory = Join-Path $PSScriptRoot 'generated'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$variants = @('viewer', 'server', 'connected', 'disabled')
foreach ($variant in $variants) {
  Write-MultiSizeIcon (Join-Path $outputDirectory "2labvnc-$variant.ico") $variant
  Write-Preview (Join-Path $outputDirectory "2labvnc-$variant.png") $variant
}

Write-AboutBitmap `
  (Join-Path $ProjectRoot 'tvnserver\res\tightvnc.bmp') `
  60 55 'server'
Write-AboutBitmap `
  (Join-Path $ProjectRoot 'tvnviewer\res\tightvnc.bmp') `
  60 55 'viewer'
Write-AboutBitmap `
  (Join-Path $ProjectRoot 'tvnviewer\res\tightvnc48.bmp') `
  32 30 'viewer'

$copyTargets = @{
  (Join-Path $ProjectRoot 'tvnviewer\res\appicon.ico') = 'viewer'
  (Join-Path $ProjectRoot 'tvnserver\res\idle.ico') = 'server'
  (Join-Path $ProjectRoot 'tvnserver\res\connected.ico') = 'connected'
  (Join-Path $ProjectRoot 'tvnserver\res\disabled.ico') = 'disabled'
  (Join-Path $ProjectRoot 'wix-installer\tvnserver.ico') = 'server'
  (Join-Path $ProjectRoot 'wix-installer\vncviewer.ico') = 'viewer'
}
foreach ($target in $copyTargets.Keys) {
  Copy-Item -LiteralPath (Join-Path $outputDirectory "2labvnc-$($copyTargets[$target]).ico") `
            -Destination $target -Force
}

Write-Output "Generated flat 2LabVnc icon family in $outputDirectory"
