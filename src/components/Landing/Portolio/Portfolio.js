import React from 'react'
import PortfolioItem from './PortfolioItem/PortfolioItem'
import './Portfolio.css'

class Portfolio extends React.Component {
    render() {
        return (
            <div>
                <div className={'portfolioHeader'}>Projects</div>
                <PortfolioItem name={'SVD Image Compression'} description={'Image Compression using singular value decomposition'} github={'https://github.com/sharath/svd-compress/'} binder={'https://mybinder.org/v2/gh/sharath/svd-compress/master?filepath=demo.ipynb'}/>
                <PortfolioItem name={'wxtlogger'} description={'Sampling software for Vaisala WXT510 Weather Stations'} github={'https://github.com/sharath/wxtlogger'}/>
                <PortfolioItem name={'terabox.space'} description={'Created a business that rented out OpenVZ-based virtualized server on a monthly basis.'}/>
            </div>
        );
    }
}

export default Portfolio;