import React from 'react'
import styles from './PortfolioItem.module.css'
import {ThemeContext} from "../../../Theme";
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

class PortfolioItem extends React.Component {
    static contextType = ThemeContext

    render() {
        return (
            <div className={cx('portfolioItem', this.context)}>
                <div className={styles.title}>{this.props.name}</div>
                <div className={styles.description}>{this.props.description}</div>
                <div className={styles.links}>
                    {this.props.custom ?
                        <a href={this.props.custom} className={cx('custom', 'portfolioExternalButton')}>
                            {this.props.customName}
                        </a> :
                        <div>&nbsp;</div>}
                    {this.props.github ?
                        <a href={this.props.github} className={cx('github', 'portfolioExternalButton')}>
                            {this.props.githubName ? this.props.githubName : "Github"}
                        </a> :
                        <div>&nbsp;</div>}
                </div>
            </div>
        );
    }
}

export default PortfolioItem;