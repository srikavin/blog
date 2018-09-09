import React from 'react';
import PropTypes from 'prop-types';

import './PostHeader.css'
import PostTags from './PostTags/PostTags';
import PostMeta from './PostMeta/PostMeta';
import Skeleton from '../../util/Skeleton/Skeleton';

class PostHeader extends React.PureComponent {
    getTitleBlock() {
        if (this.props.loading) {
            return (
                <Skeleton align='center'>
                    <h1 className={'title ' + this.props.className}>Lorem ipsum dolor sit amet</h1>
                </Skeleton>
            );
        }
        return <h1 className="title">{this.props.title}</h1>
    }

    render() {
        return (
            <div className={this.props.className}>
                {this.getTitleBlock()}
                <PostMeta createdTime={this.props.createdTime}
                          modifiedTime={this.props.modifiedTime}
                          author={this.props.author}
                          loading={this.props.loading}
                />
                <PostTags className="post-tags" tags={this.props.tags}/>
            </div>
        )
    }
}

PostHeader.propTypes = {
    loading: PropTypes.bool,
    title: PropTypes.string,
    author: PropTypes.any,
    createdTime: PropTypes.any,
    modifiedTime: PropTypes.any,
    tags: PropTypes.array,
    className: PropTypes.string
};

export default PostHeader;